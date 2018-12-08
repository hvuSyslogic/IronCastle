﻿using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class TlsClientProtocol : TlsProtocol
	{
		protected internal TlsClient tlsClient = null;
		internal TlsClientContextImpl tlsClientContext = null;

		protected internal byte[] selectedSessionID = null;

		protected internal TlsKeyExchange keyExchange = null;
		protected internal TlsAuthentication authentication = null;

		protected internal CertificateStatus certificateStatus = null;
		protected internal CertificateRequest certificateRequest = null;

		/// <summary>
		/// Constructor for blocking mode. </summary>
		/// <param name="input"> The stream of data from the server </param>
		/// <param name="output"> The stream of data to the server </param>
		/// <param name="secureRandom"> Random number generator for various cryptographic functions </param>
		public TlsClientProtocol(InputStream input, OutputStream output, SecureRandom secureRandom) : base(input, output, secureRandom)
		{
		}

		/// <summary>
		/// Constructor for non-blocking mode.<br>
		/// <br>
		/// When data is received, use <seealso cref="#offerInput(byte[])"/> to provide the received ciphertext,
		/// then use <seealso cref="#readInput(byte[], int, int)"/> to read the corresponding cleartext.<br>
		/// <br>
		/// Similarly, when data needs to be sent, use <seealso cref="#offerOutput(byte[], int, int)"/> to provide
		/// the cleartext, then use <seealso cref="#readOutput(byte[], int, int)"/> to get the corresponding
		/// ciphertext.
		/// </summary>
		/// <param name="secureRandom">
		///            Random number generator for various cryptographic functions </param>
		public TlsClientProtocol(SecureRandom secureRandom) : base(secureRandom)
		{
		}

		/// <summary>
		/// Initiates a TLS handshake in the role of client.<br>
		/// <br>
		/// In blocking mode, this will not return until the handshake is complete.
		/// In non-blocking mode, use <seealso cref="TlsPeer#notifyHandshakeComplete()"/> to
		/// receive a callback when the handshake is complete.
		/// </summary>
		/// <param name="tlsClient"> The <seealso cref="TlsClient"/> to use for the handshake. </param>
		/// <exception cref="IOException"> If in blocking mode and handshake was not successful. </exception>
		public virtual void connect(TlsClient tlsClient)
		{
			if (tlsClient == null)
			{
				throw new IllegalArgumentException("'tlsClient' cannot be null");
			}
			if (this.tlsClient != null)
			{
				throw new IllegalStateException("'connect' can only be called once");
			}

			this.tlsClient = tlsClient;

			this.securityParameters = new SecurityParameters();
			this.securityParameters.entity = ConnectionEnd.client;

			this.tlsClientContext = new TlsClientContextImpl(secureRandom, securityParameters);

			this.securityParameters.clientRandom = createRandomBlock(tlsClient.shouldUseGMTUnixTime(), tlsClientContext.getNonceRandomGenerator());

			this.tlsClient.init(tlsClientContext);
			this.recordStream.init(tlsClientContext);

			TlsSession sessionToResume = tlsClient.getSessionToResume();
			if (sessionToResume != null && sessionToResume.isResumable())
			{
				SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
				if (sessionParameters != null && sessionParameters.isExtendedMasterSecret())
				{
					this.tlsSession = sessionToResume;
					this.sessionParameters = sessionParameters;
				}
			}

			sendClientHelloMessage();
			this.connection_state = CS_CLIENT_HELLO;

			blockForHandshake();
		}

		public override void cleanupHandshake()
		{
			base.cleanupHandshake();

			this.selectedSessionID = null;
			this.keyExchange = null;
			this.authentication = null;
			this.certificateStatus = null;
			this.certificateRequest = null;
		}

		public override TlsContext getContext()
		{
			return tlsClientContext;
		}

		public override AbstractTlsContext getContextAdmin()
		{
			return tlsClientContext;
		}

		public override TlsPeer getPeer()
		{
			return tlsClient;
		}

		public override void handleHandshakeMessage(short type, ByteArrayInputStream buf)
		{
			if (this.resumedSession)
			{
				if (type != HandshakeType.finished || this.connection_state != CS_SERVER_HELLO)
				{
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				processFinishedMessage(buf);
				this.connection_state = CS_SERVER_FINISHED;

				sendChangeCipherSpecMessage();
				sendFinishedMessage();
				this.connection_state = CS_CLIENT_FINISHED;

				completeHandshake();
				return;
			}

			switch (type)
			{
			case HandshakeType.certificate:
			{
				switch (this.connection_state)
				{
				case CS_SERVER_HELLO:
				{
					handleSupplementalData(null);
					// NB: Fall through to next case label
				}
					goto case CS_SERVER_SUPPLEMENTAL_DATA;
				case CS_SERVER_SUPPLEMENTAL_DATA:
				{
					// Parse the Certificate message and send to cipher suite

					this.peerCertificate = Certificate.parse(buf);

					assertEmpty(buf);

					// TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
					if (this.peerCertificate == null || this.peerCertificate.isEmpty())
					{
						this.allowCertificateStatus = false;
					}

					this.keyExchange.processServerCertificate(this.peerCertificate);

					this.authentication = tlsClient.getAuthentication();
					this.authentication.notifyServerCertificate(this.peerCertificate);

					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				this.connection_state = CS_SERVER_CERTIFICATE;
				break;
			}
			case HandshakeType.certificate_status:
			{
				switch (this.connection_state)
				{
				case CS_SERVER_CERTIFICATE:
				{
					if (!this.allowCertificateStatus)
					{
						/*
						 * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
						 * server MUST have included an extension of type "status_request" with empty
						 * "extension_data" in the extended server hello..
						 */
						throw new TlsFatalAlert(AlertDescription.unexpected_message);
					}

					this.certificateStatus = CertificateStatus.parse(buf);

					assertEmpty(buf);

					// TODO[RFC 3546] Figure out how to provide this to the client/authentication.

					this.connection_state = CS_CERTIFICATE_STATUS;
					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}
				break;
			}
			case HandshakeType.finished:
			{
				switch (this.connection_state)
				{
				case CS_CLIENT_FINISHED:
				{
					if (this.expectSessionTicket)
					{
						/*
						 * RFC 5077 3.3. This message MUST be sent if the server included a
						 * SessionTicket extension in the ServerHello.
						 */
						throw new TlsFatalAlert(AlertDescription.unexpected_message);
					}

					// NB: Fall through to next case label
				}
					goto case CS_SERVER_SESSION_TICKET;
				case CS_SERVER_SESSION_TICKET:
				{
					processFinishedMessage(buf);
					this.connection_state = CS_SERVER_FINISHED;

					completeHandshake();
					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}
				break;
			}
			case HandshakeType.server_hello:
			{
				switch (this.connection_state)
				{
				case CS_CLIENT_HELLO:
				{
					receiveServerHelloMessage(buf);
					this.connection_state = CS_SERVER_HELLO;

					this.recordStream.notifyHelloComplete();

					applyMaxFragmentLengthExtension();

					if (this.resumedSession)
					{
						this.securityParameters.masterSecret = Arrays.clone(this.sessionParameters.getMasterSecret());
						this.recordStream.setPendingConnectionState(getPeer().getCompression(), getPeer().getCipher());
					}
					else
					{
						invalidateSession();

						if (this.selectedSessionID.Length > 0)
						{
							this.tlsSession = new TlsSessionImpl(this.selectedSessionID, null);
						}
					}

					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}
				break;
			}
			case HandshakeType.supplemental_data:
			{
				switch (this.connection_state)
				{
				case CS_SERVER_HELLO:
				{
					handleSupplementalData(readSupplementalDataMessage(buf));
					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}
				break;
			}
			case HandshakeType.server_hello_done:
			{
				switch (this.connection_state)
				{
				case CS_SERVER_HELLO:
				{
					handleSupplementalData(null);
					// NB: Fall through to next case label
				}
					goto case CS_SERVER_SUPPLEMENTAL_DATA;
				case CS_SERVER_SUPPLEMENTAL_DATA:
				{
					// There was no server certificate message; check it's OK
					this.keyExchange.skipServerCredentials();
					this.authentication = null;

					// NB: Fall through to next case label
				}
					goto case CS_SERVER_CERTIFICATE;
				case CS_SERVER_CERTIFICATE:
				case CS_CERTIFICATE_STATUS:
				{
					// There was no server key exchange message; check it's OK
					this.keyExchange.skipServerKeyExchange();

					// NB: Fall through to next case label
				}
					goto case CS_SERVER_KEY_EXCHANGE;
				case CS_SERVER_KEY_EXCHANGE:
				case CS_CERTIFICATE_REQUEST:
				{
					assertEmpty(buf);

					this.connection_state = CS_SERVER_HELLO_DONE;

					this.recordStream.getHandshakeHash().sealHashAlgorithms();

					Vector clientSupplementalData = tlsClient.getClientSupplementalData();
					if (clientSupplementalData != null)
					{
						sendSupplementalDataMessage(clientSupplementalData);
					}
					this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;

					TlsCredentials clientCreds = null;
					if (certificateRequest == null)
					{
						this.keyExchange.skipClientCredentials();
					}
					else
					{
						clientCreds = this.authentication.getClientCredentials(certificateRequest);

						if (clientCreds == null)
						{
							this.keyExchange.skipClientCredentials();

							/*
							 * RFC 5246 If no suitable certificate is available, the client MUST send a
							 * certificate message containing no certificates.
							 * 
							 * NOTE: In previous RFCs, this was SHOULD instead of MUST.
							 */
							sendCertificateMessage(Certificate.EMPTY_CHAIN);
						}
						else
						{
							this.keyExchange.processClientCredentials(clientCreds);

							sendCertificateMessage(clientCreds.getCertificate());
						}
					}

					this.connection_state = CS_CLIENT_CERTIFICATE;

					/*
					 * Send the client key exchange message, depending on the key exchange we are using
					 * in our CipherSuite.
					 */
					sendClientKeyExchangeMessage();
					this.connection_state = CS_CLIENT_KEY_EXCHANGE;

					if (TlsUtils.isSSL(getContext()))
					{
						establishMasterSecret(getContext(), keyExchange);
					}

					TlsHandshakeHash prepareFinishHash = recordStream.prepareToFinish();
					this.securityParameters.sessionHash = getCurrentPRFHash(getContext(), prepareFinishHash, null);

					if (!TlsUtils.isSSL(getContext()))
					{
						establishMasterSecret(getContext(), keyExchange);
					}

					recordStream.setPendingConnectionState(getPeer().getCompression(), getPeer().getCipher());

					if (clientCreds != null && clientCreds is TlsSignerCredentials)
					{
						TlsSignerCredentials signerCredentials = (TlsSignerCredentials)clientCreds;

						/*
						 * RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
						 */
						SignatureAndHashAlgorithm signatureAndHashAlgorithm = TlsUtils.getSignatureAndHashAlgorithm(getContext(), signerCredentials);

						byte[] hash;
						if (signatureAndHashAlgorithm == null)
						{
							hash = securityParameters.getSessionHash();
						}
						else
						{
							hash = prepareFinishHash.getFinalHash(signatureAndHashAlgorithm.getHash());
						}

						byte[] signature = signerCredentials.generateCertificateSignature(hash);
						DigitallySigned certificateVerify = new DigitallySigned(signatureAndHashAlgorithm, signature);
						sendCertificateVerifyMessage(certificateVerify);

						this.connection_state = CS_CERTIFICATE_VERIFY;
					}

					sendChangeCipherSpecMessage();
					sendFinishedMessage();
					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				this.connection_state = CS_CLIENT_FINISHED;
				break;
			}
			case HandshakeType.server_key_exchange:
			{
				switch (this.connection_state)
				{
				case CS_SERVER_HELLO:
				{
					handleSupplementalData(null);
					// NB: Fall through to next case label
				}
					goto case CS_SERVER_SUPPLEMENTAL_DATA;
				case CS_SERVER_SUPPLEMENTAL_DATA:
				{
					// There was no server certificate message; check it's OK
					this.keyExchange.skipServerCredentials();
					this.authentication = null;

					// NB: Fall through to next case label
				}
					goto case CS_SERVER_CERTIFICATE;
				case CS_SERVER_CERTIFICATE:
				case CS_CERTIFICATE_STATUS:
				{
					this.keyExchange.processServerKeyExchange(buf);

					assertEmpty(buf);
					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				this.connection_state = CS_SERVER_KEY_EXCHANGE;
				break;
			}
			case HandshakeType.certificate_request:
			{
				switch (this.connection_state)
				{
				case CS_SERVER_CERTIFICATE:
				case CS_CERTIFICATE_STATUS:
				{
					// There was no server key exchange message; check it's OK
					this.keyExchange.skipServerKeyExchange();

					// NB: Fall through to next case label
				}
					goto case CS_SERVER_KEY_EXCHANGE;
				case CS_SERVER_KEY_EXCHANGE:
				{
					if (this.authentication == null)
					{
						/*
						 * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server
						 * to request client identification.
						 */
						throw new TlsFatalAlert(AlertDescription.handshake_failure);
					}

					this.certificateRequest = CertificateRequest.parse(getContext(), buf);

					assertEmpty(buf);

					this.keyExchange.validateCertificateRequest(this.certificateRequest);

					/*
					 * TODO Give the client a chance to immediately select the CertificateVerify hash
					 * algorithm here to avoid tracking the other hash algorithms unnecessarily?
					 */
					TlsUtils.trackHashAlgorithms(this.recordStream.getHandshakeHash(), this.certificateRequest.getSupportedSignatureAlgorithms());

					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				this.connection_state = CS_CERTIFICATE_REQUEST;
				break;
			}
			case HandshakeType.session_ticket:
			{
				switch (this.connection_state)
				{
				case CS_CLIENT_FINISHED:
				{
					if (!this.expectSessionTicket)
					{
						/*
						 * RFC 5077 3.3. This message MUST NOT be sent if the server did not include a
						 * SessionTicket extension in the ServerHello.
						 */
						throw new TlsFatalAlert(AlertDescription.unexpected_message);
					}

					/*
					 * RFC 5077 3.4. If the client receives a session ticket from the server, then it
					 * discards any Session ID that was sent in the ServerHello.
					 */
					invalidateSession();

					receiveNewSessionTicketMessage(buf);
					break;
				}
				default:
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				}

				this.connection_state = CS_SERVER_SESSION_TICKET;
				break;
			}
			case HandshakeType.hello_request:
			{
				assertEmpty(buf);

				/*
				 * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
				 * client is currently negotiating a session. This message may be ignored by the client
				 * if it does not wish to renegotiate a session, or the client may, if it wishes,
				 * respond with a no_renegotiation alert.
				 */
				if (this.connection_state == CS_END)
				{
					refuseRenegotiation();
				}
				break;
			}
			case HandshakeType.client_hello:
			case HandshakeType.client_key_exchange:
			case HandshakeType.certificate_verify:
			case HandshakeType.hello_verify_request:
			default:
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual void handleSupplementalData(Vector serverSupplementalData)
		{
			this.tlsClient.processServerSupplementalData(serverSupplementalData);
			this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

			this.keyExchange = tlsClient.getKeyExchange();
			this.keyExchange.init(getContext());
		}

		public virtual void receiveNewSessionTicketMessage(ByteArrayInputStream buf)
		{
			NewSessionTicket newSessionTicket = NewSessionTicket.parse(buf);

			assertEmpty(buf);

			tlsClient.notifyNewSessionTicket(newSessionTicket);
		}

		public virtual void receiveServerHelloMessage(ByteArrayInputStream buf)
		{
			{
				ProtocolVersion server_version = TlsUtils.readVersion(buf);
				if (server_version.isDTLS())
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}

				// Check that this matches what the server is sending in the record layer
				if (!server_version.Equals(this.recordStream.getReadVersion()))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}

				ProtocolVersion client_version = getContext().getClientVersion();
				if (!server_version.isEqualOrEarlierVersionOf(client_version))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}

				this.recordStream.setWriteVersion(server_version);
				getContextAdmin().setServerVersion(server_version);
				this.tlsClient.notifyServerVersion(server_version);
			}

			/*
			 * Read the server random
			 */
			this.securityParameters.serverRandom = TlsUtils.readFully(32, buf);

			this.selectedSessionID = TlsUtils.readOpaque8(buf);
			if (this.selectedSessionID.Length > 32)
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}
			this.tlsClient.notifySessionID(this.selectedSessionID);
			this.resumedSession = this.selectedSessionID.Length > 0 && this.tlsSession != null && Arrays.areEqual(this.selectedSessionID, this.tlsSession.getSessionID());

			/*
			 * Find out which CipherSuite the server has chosen and check that it was one of the offered
			 * ones, and is a valid selection for the negotiated version.
			 */
			int selectedCipherSuite = TlsUtils.readUint16(buf);
			if (!Arrays.contains(this.offeredCipherSuites, selectedCipherSuite) || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL || CipherSuite.isSCSV(selectedCipherSuite) || !TlsUtils.isValidCipherSuiteForVersion(selectedCipherSuite, getContext().getServerVersion()))
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}
			this.tlsClient.notifySelectedCipherSuite(selectedCipherSuite);

			/*
			 * Find out which CompressionMethod the server has chosen and check that it was one of the
			 * offered ones.
			 */
			short selectedCompressionMethod = TlsUtils.readUint8(buf);
			if (!Arrays.contains(this.offeredCompressionMethods, selectedCompressionMethod))
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}
			this.tlsClient.notifySelectedCompressionMethod(selectedCompressionMethod);

			/*
			 * RFC 3546 2.2 The extended server hello message format MAY be sent in place of the server
			 * hello message when the client has requested extended functionality via the extended
			 * client hello message specified in Section 2.1. ... Note that the extended server hello
			 * message is only sent in response to an extended client hello message. This prevents the
			 * possibility that the extended server hello message could "break" existing TLS 1.0
			 * clients.
			 */
			this.serverExtensions = readExtensions(buf);

			/*
			 * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
			 * master secret [..]. (and see 5.2, 5.3)
			 */
			this.securityParameters.extendedMasterSecret = !TlsUtils.isSSL(tlsClientContext) && TlsExtensionsUtils.hasExtendedMasterSecretExtension(serverExtensions);

			if (!securityParameters.isExtendedMasterSecret() && (resumedSession || tlsClient.requiresExtendedMasterSecret()))
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}

			/*
			 * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
			 * extended client hello message.
			 * 
			 * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
			 * Hello is always allowed.
			 */
			if (this.serverExtensions != null)
			{
				Enumeration e = this.serverExtensions.keys();
				while (e.hasMoreElements())
				{
					int? extType = (int?)e.nextElement();

					/*
					 * RFC 5746 3.6. Note that sending a "renegotiation_info" extension in response to a
					 * ClientHello containing only the SCSV is an explicit exception to the prohibition
					 * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
					 * only allowed because the client is signaling its willingness to receive the
					 * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
					 */
					if (extType.Equals(EXT_RenegotiationInfo))
					{
						continue;
					}

					/*
					 * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless the
					 * same extension type appeared in the corresponding ClientHello. If a client
					 * receives an extension type in ServerHello that it did not request in the
					 * associated ClientHello, it MUST abort the handshake with an unsupported_extension
					 * fatal alert.
					 */
					if (null == TlsUtils.getExtensionData(this.clientExtensions, extType))
					{
						throw new TlsFatalAlert(AlertDescription.unsupported_extension);
					}

					/*
					 * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
					 * extensions appearing in the client hello, and send a server hello containing no
					 * extensions[.]
					 */
					if (this.resumedSession)
					{
						// TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
						// TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
						// TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
	//                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
					}
				}
			}

			/*
			 * RFC 5746 3.4. Client Behavior: Initial Handshake
			 */
			{
				/*
				 * When a ServerHello is received, the client MUST check if it includes the
				 * "renegotiation_info" extension:
				 */
				byte[] renegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
				if (renegExtData != null)
				{
					/*
					 * If the extension is present, set the secure_renegotiation flag to TRUE. The
					 * client MUST then verify that the length of the "renegotiated_connection"
					 * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
					 * handshake_failure alert).
					 */
					this.secure_renegotiation = true;

					if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
					{
						throw new TlsFatalAlert(AlertDescription.handshake_failure);
					}
				}
			}

			// TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
			this.tlsClient.notifySecureRenegotiation(this.secure_renegotiation);

			Hashtable sessionClientExtensions = clientExtensions, sessionServerExtensions = serverExtensions;
			if (this.resumedSession)
			{
				if (selectedCipherSuite != this.sessionParameters.getCipherSuite() || selectedCompressionMethod != this.sessionParameters.getCompressionAlgorithm())
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}

				sessionClientExtensions = null;
				sessionServerExtensions = this.sessionParameters.readServerExtensions();
			}

			this.securityParameters.cipherSuite = selectedCipherSuite;
			this.securityParameters.compressionAlgorithm = selectedCompressionMethod;

			if (sessionServerExtensions != null && !sessionServerExtensions.isEmpty())
			{
				{
					/*
					 * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
					 * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
					 * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
					 * client.
					 */
					bool serverSentEncryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(sessionServerExtensions);
					if (serverSentEncryptThenMAC && !TlsUtils.isBlockCipherSuite(selectedCipherSuite))
					{
						throw new TlsFatalAlert(AlertDescription.illegal_parameter);
					}
					this.securityParameters.encryptThenMAC = serverSentEncryptThenMAC;
				}

				this.securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

				this.securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(sessionServerExtensions);

				/*
				 * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
				 * a session resumption handshake.
				 */
				this.allowCertificateStatus = !this.resumedSession && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsExtensionsUtils.EXT_status_request, AlertDescription.illegal_parameter);

				this.expectSessionTicket = !this.resumedSession && TlsUtils.hasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket, AlertDescription.illegal_parameter);
			}

			if (sessionClientExtensions != null)
			{
				this.tlsClient.processServerExtensions(sessionServerExtensions);
			}

			this.securityParameters.prfAlgorithm = getPRFAlgorithm(getContext(), this.securityParameters.getCipherSuite());

			/*
			 * RFC 5246 7.4.9. Any cipher suite which does not explicitly specify
			 * verify_data_length has a verify_data_length equal to 12. This includes all
			 * existing cipher suites.
			 */
			this.securityParameters.verifyDataLength = 12;
		}

		public virtual void sendCertificateVerifyMessage(DigitallySigned certificateVerify)
		{
			HandshakeMessage message = new HandshakeMessage(this, HandshakeType.certificate_verify);

			certificateVerify.encode(message);

			message.writeToRecordStream();
		}

		public virtual void sendClientHelloMessage()
		{
			this.recordStream.setWriteVersion(this.tlsClient.getClientHelloRecordLayerVersion());

			ProtocolVersion client_version = this.tlsClient.getClientVersion();
			if (client_version.isDTLS())
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			getContextAdmin().setClientVersion(client_version);

			/*
			 * TODO RFC 5077 3.4. When presenting a ticket, the client MAY generate and include a
			 * Session ID in the TLS ClientHello.
			 */
			byte[] session_id = TlsUtils.EMPTY_BYTES;
			if (this.tlsSession != null)
			{
				session_id = this.tlsSession.getSessionID();
				if (session_id == null || session_id.Length > 32)
				{
					session_id = TlsUtils.EMPTY_BYTES;
				}
			}

			bool fallback = this.tlsClient.isFallback();

			this.offeredCipherSuites = this.tlsClient.getCipherSuites();

			this.offeredCompressionMethods = this.tlsClient.getCompressionMethods();

			if (session_id.Length > 0 && this.sessionParameters != null)
			{
				if (!sessionParameters.isExtendedMasterSecret() || !Arrays.contains(this.offeredCipherSuites, sessionParameters.getCipherSuite()) || !Arrays.contains(this.offeredCompressionMethods, sessionParameters.getCompressionAlgorithm()))
				{
					session_id = TlsUtils.EMPTY_BYTES;
				}
			}

			this.clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.tlsClient.getClientExtensions());

			if (!client_version.isSSL())
			{
				TlsExtensionsUtils.addExtendedMasterSecretExtension(this.clientExtensions);
			}

			HandshakeMessage message = new HandshakeMessage(this, HandshakeType.client_hello);

			TlsUtils.writeVersion(client_version, message);

			message.write(this.securityParameters.getClientRandom());

			TlsUtils.writeOpaque8(session_id, message);

			{
			// Cipher Suites (and SCSV)
				/*
				 * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
				 * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
				 * ClientHello. Including both is NOT RECOMMENDED.
				 */
				byte[] renegExtData = TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo);
				bool noRenegExt = (null == renegExtData);

				bool noRenegSCSV = !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

				if (noRenegExt && noRenegSCSV)
				{
					// TODO Consider whether to default to a client extension instead
					this.offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
				}

				/*
				 * RFC 7507 4. If a client sends a ClientHello.client_version containing a lower value
				 * than the latest (highest-valued) version supported by the client, it SHOULD include
				 * the TLS_FALLBACK_SCSV cipher suite value in ClientHello.cipher_suites [..]. (The
				 * client SHOULD put TLS_FALLBACK_SCSV after all cipher suites that it actually intends
				 * to negotiate.)
				 */
				if (fallback && !Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV))
				{
					this.offeredCipherSuites = Arrays.append(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
				}

				TlsUtils.writeUint16ArrayWithUint16Length(offeredCipherSuites, message);
			}

			TlsUtils.writeUint8ArrayWithUint8Length(offeredCompressionMethods, message);

			writeExtensions(message, clientExtensions);

			message.writeToRecordStream();
		}

		public virtual void sendClientKeyExchangeMessage()
		{
			HandshakeMessage message = new HandshakeMessage(this, HandshakeType.client_key_exchange);

			this.keyExchange.generateClientKeyExchange(message);

			message.writeToRecordStream();
		}
	}

}