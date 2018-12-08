using System;

namespace org.bouncycastle.est.jcajce
{


	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using KeyPurposeId = org.bouncycastle.asn1.x509.KeyPurposeId;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;


	/// <summary>
	/// General utility methods for building common objects for supporting the JCA/JCE/JSSE.
	/// </summary>
	public class JcaJceUtils
	{

		public static X509TrustManager getTrustAllTrustManager()
		{

			//
			// Trust manager signal distrust by throwing exceptions.
			// This one trust all by doing nothing.
			//

			return new X509TrustManagerAnonymousInnerClass();

		}

		public class X509TrustManagerAnonymousInnerClass : X509TrustManager
		{
			public void checkClientTrusted(X509Certificate[] x509Certificates, string s)
			{

			}

			public void checkServerTrusted(X509Certificate[] x509Certificates, string s)
			{

			}

			public X509Certificate[] getAcceptedIssuers()
			{
				return new X509Certificate[0];
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static javax.net.ssl.X509TrustManager[] getCertPathTrustManager(final java.util.Set<java.security.cert.TrustAnchor> anchors, final java.security.cert.CRL[] revocationLists)
		public static X509TrustManager[] getCertPathTrustManager(Set<TrustAnchor> anchors, CRL[] revocationLists)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.cert.X509Certificate[] x509CertificateTrustAnchors = new java.security.cert.X509Certificate[anchors.size()];
			X509Certificate[] x509CertificateTrustAnchors = new X509Certificate[anchors.size()];
			int c = 0;
			for (Iterator it = anchors.iterator(); it.hasNext();)
			{
				TrustAnchor ta = (TrustAnchor)it.next();

				x509CertificateTrustAnchors[c++] = ta.getTrustedCert();
			}

			return new X509TrustManager[]{new X509TrustManagerAnonymousInnerClass2(anchors, revocationLists, x509CertificateTrustAnchors)};
		}

		public class X509TrustManagerAnonymousInnerClass2 : X509TrustManager
		{
			private Set<TrustAnchor> anchors;
			private CRL[] revocationLists;
			private X509Certificate[] x509CertificateTrustAnchors;

			public X509TrustManagerAnonymousInnerClass2(Set<TrustAnchor> anchors, CRL[] revocationLists, X509Certificate[] x509CertificateTrustAnchors)
			{
				this.anchors = anchors;
				this.revocationLists = revocationLists;
				this.x509CertificateTrustAnchors = x509CertificateTrustAnchors;
			}

			public void checkClientTrusted(X509Certificate[] x509Certificates, string s)
			{

			}

			public void checkServerTrusted(X509Certificate[] x509Certificates, string s)
			{
				try
				{
					CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(x509Certificates)), "BC");

					CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");

					X509CertSelector constraints = new X509CertSelector();

					constraints.setCertificate(x509Certificates[0]);


					PKIXBuilderParameters param = new PKIXBuilderParameters(anchors, constraints);
					param.addCertStore(certStore);
					if (revocationLists != null)
					{
						param.setRevocationEnabled(true);
						param.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(revocationLists))));
					}
					else
					{
						param.setRevocationEnabled(false);
					}

					PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)pathBuilder.build(param);

					validateServerCertUsage(x509Certificates[0]);

				}
				catch (CertificateException e)
				{
					throw e;
				}
				catch (GeneralSecurityException e)
				{
					throw new CertificateException("unable to process certificates: " + e.Message, e);
				}
			}

			public X509Certificate[] getAcceptedIssuers()
			{
				X509Certificate[] rv = new X509Certificate[x509CertificateTrustAnchors.Length];

				JavaSystem.arraycopy(x509CertificateTrustAnchors, 0, rv, 0, rv.Length);

				return rv;
			}
		}

		public static void validateServerCertUsage(X509Certificate x509Certificate)
		{
			try
			{
				X509CertificateHolder cert = new X509CertificateHolder(x509Certificate.getEncoded());

				KeyUsage keyUsage = KeyUsage.fromExtensions(cert.getExtensions());

				if (keyUsage != null)
				{
					if (keyUsage.hasUsages(KeyUsage.keyCertSign))
					{
						throw new CertificateException("Key usage must not contain keyCertSign");
					}

					if (!(keyUsage.hasUsages(KeyUsage.digitalSignature) || keyUsage.hasUsages(KeyUsage.keyEncipherment)))
					{
						throw new CertificateException("Key usage must be none, digitalSignature or keyEncipherment");
					}
				}

				//
				// Check extended key usage.
				//
				ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.fromExtensions(cert.getExtensions());

				if (extendedKeyUsage != null)
				{
					if (!(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth) || extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_msSGC) || extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_nsSGC)))
					{
						throw new CertificateException("Certificate extended key usage must include serverAuth, msSGC or nsSGC");
					}
				}

			}
			catch (CertificateException c)
			{
				throw c;
			}
			catch (Exception e)
			{
				throw new CertificateException(e.Message, e);
			}
		}


		public static KeyManagerFactory createKeyManagerFactory(string type, string provider, KeyStore clientKeyStore, char[] clientKeyStorePass)
		{
			KeyManagerFactory keyManagerFactory = null;
			if (string.ReferenceEquals(type, null) && string.ReferenceEquals(provider, null))
			{
				keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			}
			else if (string.ReferenceEquals(provider, null))
			{
				keyManagerFactory = KeyManagerFactory.getInstance(type);
			}
			else
			{
				keyManagerFactory = KeyManagerFactory.getInstance(type, provider);
			}
			keyManagerFactory.init(clientKeyStore, clientKeyStorePass);
			return keyManagerFactory;
		}
	}

}