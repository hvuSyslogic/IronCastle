using org.bouncycastle.crypto.tls;

using System;

namespace org.bouncycastle.crypto.tls.test
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Arrays = org.bouncycastle.util.Arrays;

	public class TlsTestClientImpl : DefaultTlsClient
	{
		protected internal readonly TlsTestConfig config;

		protected internal int firstFatalAlertConnectionEnd = -1;
		protected internal short firstFatalAlertDescription = -1;

		public TlsTestClientImpl(TlsTestConfig config)
		{
			this.config = config;
		}

		public virtual int getFirstFatalAlertConnectionEnd()
		{
			return firstFatalAlertConnectionEnd;
		}

		public virtual short getFirstFatalAlertDescription()
		{
			return firstFatalAlertDescription;
		}

		public override ProtocolVersion getClientVersion()
		{
			if (config.clientOfferVersion != null)
			{
				return config.clientOfferVersion;
			}

			return base.getClientVersion();
		}

		public override ProtocolVersion getMinimumVersion()
		{
			if (config.clientMinimumVersion != null)
			{
				return config.clientMinimumVersion;
			}

			return base.getMinimumVersion();
		}

		public override Hashtable getClientExtensions()
		{
			Hashtable clientExtensions = base.getClientExtensions();
			if (clientExtensions != null && !config.clientSendSignatureAlgorithms)
			{
				clientExtensions.remove(TlsUtils.EXT_signature_algorithms);
				this.supportedSignatureAlgorithms = null;
			}
			return clientExtensions;
		}

		public override bool isFallback()
		{
			return config.clientFallback;
		}

		public override void notifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
		{
			if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
			{
				firstFatalAlertConnectionEnd = ConnectionEnd.client;
				firstFatalAlertDescription = alertDescription;
			}

			if (TlsTestConfig.DEBUG)
			{
				PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
				@out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
				if (!string.ReferenceEquals(message, null))
				{
					@out.println("> " + message);
				}
				if (cause != null)
				{
					cause.printStackTrace(@out);
				}
			}
		}

		public override void notifyAlertReceived(short alertLevel, short alertDescription)
		{
			if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
			{
				firstFatalAlertConnectionEnd = ConnectionEnd.server;
				firstFatalAlertDescription = alertDescription;
			}

			if (TlsTestConfig.DEBUG)
			{
				PrintStream @out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
				@out.println("TLS client received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
			}
		}

		public override void notifyServerVersion(ProtocolVersion serverVersion)
		{
			base.notifyServerVersion(serverVersion);

			if (TlsTestConfig.DEBUG)
			{
				JavaSystem.@out.println("TLS client negotiated " + serverVersion);
			}
		}

		public override TlsAuthentication getAuthentication()
		{
			return new TlsAuthenticationAnonymousInnerClass(this);
		}

		public class TlsAuthenticationAnonymousInnerClass : TlsAuthentication
		{
			private readonly TlsTestClientImpl outerInstance;

			public TlsAuthenticationAnonymousInnerClass(TlsTestClientImpl outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public void notifyServerCertificate(Certificate serverCertificate)
			{
				bool isEmpty = serverCertificate == null || serverCertificate.isEmpty();

				Certificate[] chain = serverCertificate.getCertificateList();

				// TODO Cache test resources?
				if (isEmpty || !(chain[0].Equals(TlsTestUtils.loadCertificateResource("x509-server.pem")) || chain[0].Equals(TlsTestUtils.loadCertificateResource("x509-server-dsa.pem")) || chain[0].Equals(TlsTestUtils.loadCertificateResource("x509-server-ecdsa.pem"))))
				{
					throw new TlsFatalAlert(AlertDescription.bad_certificate);
				}

				if (TlsTestConfig.DEBUG)
				{
					JavaSystem.@out.println("TLS client received server certificate chain of length " + chain.Length);
					for (int i = 0; i != chain.Length; i++)
					{
						Certificate entry = chain[i];
						// TODO Create fingerprint based on certificate signature algorithm digest
						JavaSystem.@out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject() + ")");
					}
				}
			}

			public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
			{
				if (outerInstance.config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
				{
					throw new IllegalStateException();
				}
				if (outerInstance.config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE)
				{
					return null;
				}

				short[] certificateTypes = certificateRequest.getCertificateTypes();
				if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
				{
					return null;
				}

				Vector supportedSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
				if (supportedSigAlgs != null && outerInstance.config.clientAuthSigAlg != null)
				{
					supportedSigAlgs = new Vector(1);
					supportedSigAlgs.addElement(outerInstance.config.clientAuthSigAlg);
				}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.tls.TlsSignerCredentials signerCredentials = TlsTestUtils.loadSignerCredentials(context, supportedSigAlgs, org.bouncycastle.crypto.tls.SignatureAlgorithm.rsa, "x509-client.pem", "x509-client-key.pem");
				TlsSignerCredentials signerCredentials = TlsTestUtils.loadSignerCredentials(outerInstance.context, supportedSigAlgs, SignatureAlgorithm.rsa, "x509-client.pem", "x509-client-key.pem");

				if (outerInstance.config.clientAuth == TlsTestConfig.CLIENT_AUTH_VALID)
				{
					return signerCredentials;
				}

				return new TlsSignerCredentialsAnonymousInnerClass(this, signerCredentials);
			}

			public class TlsSignerCredentialsAnonymousInnerClass : TlsSignerCredentials
			{
				private readonly TlsAuthenticationAnonymousInnerClass outerInstance;

				private TlsSignerCredentials signerCredentials;

				public TlsSignerCredentialsAnonymousInnerClass(TlsAuthenticationAnonymousInnerClass outerInstance, TlsSignerCredentials signerCredentials)
				{
					this.outerInstance = outerInstance;
					this.signerCredentials = signerCredentials;
				}

				public byte[] generateCertificateSignature(byte[] hash)
				{
					byte[] sig = signerCredentials.generateCertificateSignature(hash);

					if (outerInstance.outerInstance.config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
					{
						sig = outerInstance.outerInstance.corruptBit(sig);
					}

					return sig;
				}

				public Certificate getCertificate()
				{
					Certificate cert = signerCredentials.getCertificate();

					if (outerInstance.outerInstance.config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_CERT)
					{
						cert = outerInstance.outerInstance.corruptCertificate(cert);
					}

					return cert;
				}

				public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
				{
					return signerCredentials.getSignatureAndHashAlgorithm();
				}
			}
		}

		public virtual Certificate corruptCertificate(Certificate cert)
		{
			Certificate[] certList = cert.getCertificateList();
			certList[0] = corruptCertificateSignature(certList[0]);
			return new Certificate(certList);
		}

		public virtual Certificate corruptCertificateSignature(Certificate cert)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(cert.getTBSCertificate());
			v.add(cert.getSignatureAlgorithm());
			v.add(corruptSignature(cert.getSignature()));

			return Certificate.getInstance(new DERSequence(v));
		}

		public virtual DERBitString corruptSignature(DERBitString bs)
		{
			return new DERBitString(corruptBit(bs.getOctets()));
		}

		public virtual byte[] corruptBit(byte[] bs)
		{
			bs = Arrays.clone(bs);

			// Flip a random bit
			int bit = context.getSecureRandom().nextInt(bs.Length << 3);
			bs[(int)((uint)bit >> 3)] ^= (byte)(1 << (bit & 7));

			return bs;
		}
	}

}