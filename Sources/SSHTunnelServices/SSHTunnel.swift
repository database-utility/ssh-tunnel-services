import Crypto
import Dispatch
import Foundation
import NIO
import NIOSSH

/// The principal class for tunneling traffic through SSH.
@available(macOS 11, iOS 14, watchOS 7, tvOS 14, *)
public class SSHTunnel {
  private let group: EventLoopGroup
  private var serverChannel: Channel!
  
  /// The local TCP/IP port end of the tunnel.
  ///
  /// Connect to this port to connect through the tunnel.
  public var localPort: Int = -1
  
  /// Creates an SSH tunnel instance with the specified properties and credentials.
  /// - Parameters:
  ///   - host: The hostname of the tunnel server.
  ///   - port: The port of the tunnel server.
  ///   - targetHost: The hostname of the target host.
  ///   - targetPort: The port of the target host.
  public init(
    host: String,
    port: Int,
    username: String,
    password: String?,
    privateKey: String?,
    targetHost: String,
    targetPort: Int
  ) throws {
    group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    
    let bootstrap = ClientBootstrap(group: group)
      .channelInitializer { channel in
        channel.pipeline.addHandlers([
          NIOSSHHandler(
            role: .client(.init(
              userAuthDelegate: AuthenticationDelegate(username: username, password: password, privateKey: privateKey),
              serverAuthDelegate: AcceptAllHostKeysDelegate()
            )),
            allocator: channel.allocator,
            inboundChildChannelInitializer: nil
          ),
          ErrorHandler()
        ])
      }
      .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
      .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
    
    let channel = try bootstrap.connect(host: host, port: port).wait()
    
    let server = PortForwardingServer(group: group) { inboundChannel in
//      print(inboundChannel.remoteAddress as Any)
      
      // This block executes whenever a new inbound channel is received. We want to forward it to the peer.
      // To do that, we have to begin by creating a new SSH channel of the appropriate type.
      return channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
//        print("received inbound channel")
        
        let promise = inboundChannel.eventLoop.makePromise(of: Channel.self)
        let directTCPIP = SSHChannelType.DirectTCPIP(
          targetHost: targetHost,
          targetPort: targetPort,
          originatorAddress: inboundChannel.remoteAddress!
        )
        
        sshHandler.createChannel(promise, channelType: .directTCPIP(directTCPIP)) { childChannel, channelType in
          guard case .directTCPIP = channelType else {
            return channel.eventLoop.makeFailedFuture(Error.invalidChannelType)
          }
          
          // Attach a pair of glue handlers, one in the inbound channel and one in the outbound one.
          // We also add an error handler to both channels, and a wrapper handler to the SSH child channel to
          // encapsulate the data in SSH messages.
          // When the glue handlers are in, we can create both channels.
          let (ours, theirs) = GlueHandler.matchedPair()
          return childChannel.pipeline.addHandlers([SSHWrapperHandler(), ours, ErrorHandler()]).flatMap {
            inboundChannel.pipeline.addHandlers([theirs, ErrorHandler()])
          }
        }
        
        // We need to erase the channel here: we just want success or failure info.
        return promise.futureResult.map { _ in }
      }
    }
    
    let semaphore = DispatchSemaphore(value: 0)
    _ = server.run().map { self.serverChannel = $0; semaphore.signal() }
    semaphore.wait()
    
    localPort = serverChannel.localAddress!.port!
    
//    Task.init {
//      self.wait()
//    }
  }
  
  /// Stop the SSH tunnel.
  ///
  /// Call this method to stop the SSH tunnel.
  public func disconnect() {
    try? group.syncShutdownGracefully()
  }
  
//  func wait() {
//    // Run the server until complete
//    try! serverChannel.closeFuture.wait()
//    print("done running server")
//  }
  
  /// An SSH tunnel error.
  public enum Error: Swift.Error {
    /// Password authentication not supported error.
    case passwordAuthenticationNotSupported
    /// Public key authentication not supported error.
    case publicKeyAuthenticationNotSupported
    /// Invalid channel type error.
    case invalidChannelType
    /// Invalid data error.
    case invalidData
    /// Other error.
    case other
  }
  
  class ErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
      print("Error in SSH tunnel: \(error)")
      context.close(promise: nil)
    }
  }
  
  class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
      validationCompletePromise.succeed(())
    }
  }
  
  class AuthenticationDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let queue: DispatchQueue = DispatchQueue(label: "local.DatabaseUtility.ssh.AuthenticationDelegate")
    
    private var username: String
    private var password: String?
    private var privateKey: String?
    
    init(username: String, password: String? = nil, privateKey: String? = nil) {
      self.username = username
      self.password = password
      self.privateKey = privateKey
    }
    
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods, nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
      if let password = password {
        guard availableMethods.contains(.password) else {
          print("Error: password auth not supported")
          nextChallengePromise.fail(Error.passwordAuthenticationNotSupported)
          return
        }
        
        self.queue.async {
          nextChallengePromise.succeed(.init(
            username: self.username,
            serviceName: "",
            offer: .password(.init(password: password))
          ))
        }
      } else if let privateKey = privateKey {
        guard availableMethods.contains(.publicKey) else {
          print("Error: public key auth not supported")
          nextChallengePromise.fail(Error.publicKeyAuthenticationNotSupported)
          return
        }
        
        let key = try! Curve25519.Signing.PrivateKey(sshpemRepresentation: privateKey)
        
        self.queue.async {
          nextChallengePromise.succeed(.init(
            username: self.username,
            serviceName: "",
            offer: .privateKey(.init(privateKey: .init(ed25519Key: key)))
          ))
        }
      } else {
        fatalError()
      }
    }
  }
  
  class PortForwardingServer {
    private var serverChannel: Channel?
    private let serverLoop: EventLoop
    private let group: EventLoopGroup
    private let bindHost: String
    private let bindPort: Int
    private let forwardingChannelConstructor: (Channel) -> EventLoopFuture<Void>
    
    init(
      group: EventLoopGroup,
      bindHost: String = "localhost",
      bindPort: Int = 0,
      _ forwardingChannelConstructor: @escaping (Channel) -> EventLoopFuture<Void>
    ) {
      self.serverLoop = group.next()
      self.group = group
      self.forwardingChannelConstructor = forwardingChannelConstructor
      self.bindHost = bindHost
      self.bindPort = bindPort
    }
    
    func run() -> EventLoopFuture<Channel> {
      ServerBootstrap(group: self.serverLoop, childGroup: self.group)
        .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer(self.forwardingChannelConstructor)
        .bind(host: self.bindHost, port: self.bindPort)
        .map {
          self.serverChannel = $0
          return $0
        }
    }
    
    func close() -> EventLoopFuture<Void> {
      self.serverLoop.flatSubmit {
        guard let server = self.serverChannel else {
          // The server wasn't created yet, so we can just shut down straight away and let
          // the OS clean us up.
          return self.serverLoop.makeSucceededFuture(())
        }
        
        return server.close()
      }
    }
  }
  
  /// A simple handler that wraps data into SSHChannelData for forwarding.
  class SSHWrapperHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      let data = self.unwrapInboundIn(data)
      
      guard case .channel = data.type, case .byteBuffer(let buffer) = data.data else {
        context.fireErrorCaught(Error.invalidData)
        return
      }
      
      context.fireChannelRead(self.wrapInboundOut(buffer))
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
      let data = self.unwrapOutboundIn(data)
      let wrapped = SSHChannelData(type: .channel, data: .byteBuffer(data))
      context.write(self.wrapOutboundOut(wrapped), promise: promise)
    }
  }
  
  final class GlueHandler: ChannelDuplexHandler {
    private var partner: GlueHandler?
    
    private var context: ChannelHandlerContext?
    
    private var pendingRead: Bool = false
    
    private init() {}

    static func matchedPair() -> (GlueHandler, GlueHandler) {
      let first = GlueHandler()
      let second = GlueHandler()
      
      first.partner = second
      second.partner = first
      
      return (first, second)
    }

    private func partnerWrite(_ data: NIOAny) {
      self.context?.write(data, promise: nil)
    }
    
    private func partnerFlush() {
      self.context?.flush()
    }
    
    private func partnerWriteEOF() {
      self.context?.close(mode: .output, promise: nil)
    }
    
    private func partnerCloseFull() {
      self.context?.close(promise: nil)
    }
    
    private func partnerBecameWritable() {
      if self.pendingRead {
        self.pendingRead = false
        self.context?.read()
      }
    }
    
    private var partnerWritable: Bool {
      self.context?.channel.isWritable ?? false
    }

    typealias InboundIn = NIOAny
    typealias OutboundIn = NIOAny
    typealias OutboundOut = NIOAny
    
    func handlerAdded(context: ChannelHandlerContext) {
      self.context = context
      
      // It's possible our partner asked if we were writable, before, and we couldn't answer.
      // Consider updating it.
      if context.channel.isWritable {
        self.partner?.partnerBecameWritable()
      }
    }
    
    func handlerRemoved(context: ChannelHandlerContext) {
      self.context = nil
      self.partner = nil
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      self.partner?.partnerWrite(data)
    }
    
    func channelReadComplete(context: ChannelHandlerContext) {
      self.partner?.partnerFlush()
    }
    
    func channelInactive(context: ChannelHandlerContext) {
      self.partner?.partnerCloseFull()
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
      if let event = event as? ChannelEvent, case .inputClosed = event {
        // We have read EOF.
        self.partner?.partnerWriteEOF()
      }
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
      self.partner?.partnerCloseFull()
    }
    
    func channelWritabilityChanged(context: ChannelHandlerContext) {
      if context.channel.isWritable {
        self.partner?.partnerBecameWritable()
      }
    }
    
    func read(context: ChannelHandlerContext) {
      if let partner = self.partner, partner.partnerWritable {
        context.read()
      } else {
        self.pendingRead = true
      }
    }
  }
}
