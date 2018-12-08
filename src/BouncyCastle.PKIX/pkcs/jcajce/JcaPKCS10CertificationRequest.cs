using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.pkcs.jcajce
{

	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaPKCS10CertificationRequest : PKCS10CertificationRequest
	{
		private static Hashtable keyAlgorithms = new Hashtable();

		static JcaPKCS10CertificationRequest()
		{
			//
			// key types
			//
			keyAlgorithms.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			keyAlgorithms.put(X9ObjectIdentifiers_Fields.id_dsa, "DSA");
		}

		private JcaJceHelper helper = new DefaultJcaJceHelper();

		public JcaPKCS10CertificationRequest(CertificationRequest certificationRequest) : base(certificationRequest)
		{
		}

		public JcaPKCS10CertificationRequest(byte[] encoding) : base(encoding)
		{
		}

		public JcaPKCS10CertificationRequest(PKCS10CertificationRequest requestHolder) : base(requestHolder.toASN1Structure())
		{
		}

		public virtual JcaPKCS10CertificationRequest setProvider(string providerName)
		{
			helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcaPKCS10CertificationRequest setProvider(Provider provider)
		{
			helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual PublicKey getPublicKey()
		{
			try
			{
				SubjectPublicKeyInfo keyInfo = this.getSubjectPublicKeyInfo();
				X509EncodedKeySpec xspec = new X509EncodedKeySpec(keyInfo.getEncoded());
				KeyFactory kFact;

				try
				{
					kFact = helper.createKeyFactory(keyInfo.getAlgorithm().getAlgorithm().getId());
				}
				catch (NoSuchAlgorithmException e)
				{
					//
					// try an alternate
					//
					if (keyAlgorithms.get(keyInfo.getAlgorithm().getAlgorithm()) != null)
					{
						string keyAlgorithm = (string)keyAlgorithms.get(keyInfo.getAlgorithm().getAlgorithm());

						kFact = helper.createKeyFactory(keyAlgorithm);
					}
					else
					{
						throw e;
					}
				}

				return kFact.generatePublic(xspec);
			}
			catch (InvalidKeySpecException)
			{
				throw new InvalidKeyException("error decoding public key");
			}
			catch (IOException)
			{
				throw new InvalidKeyException("error extracting key encoding");
			}
			catch (NoSuchProviderException e)
			{
				throw new NoSuchAlgorithmException("cannot find provider: " + e.Message);
			}
		}
	}

}