using org.bouncycastle.asn1.mozilla;

using System;

namespace org.bouncycastle.mozilla.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	/// <summary>
	/// This is designed to parse the SignedPublicKeyAndChallenge created by the
	/// KEYGEN tag included by Mozilla based browsers.
	///  <pre>
	///  PublicKeyAndChallenge ::= SEQUENCE {
	///    spki SubjectPublicKeyInfo,
	///    challenge IA5STRING
	///  }
	/// 
	///  SignedPublicKeyAndChallenge ::= SEQUENCE {
	///    publicKeyAndChallenge PublicKeyAndChallenge,
	///    signatureAlgorithm AlgorithmIdentifier,
	///    signature BIT STRING
	///  }
	///  </pre>
	/// </summary>
	public class JcaSignedPublicKeyAndChallenge : SignedPublicKeyAndChallenge
	{
		internal JcaJceHelper helper = new DefaultJcaJceHelper();

		private JcaSignedPublicKeyAndChallenge(SignedPublicKeyAndChallenge @struct, JcaJceHelper helper) : base(@struct)
		{
			this.helper = helper;
		}

		public JcaSignedPublicKeyAndChallenge(byte[] bytes) : base(bytes)
		{
		}

		public virtual JcaSignedPublicKeyAndChallenge setProvider(string providerName)
		{
			return new JcaSignedPublicKeyAndChallenge(this.spkacSeq, new NamedJcaJceHelper(providerName));
		}

		public virtual JcaSignedPublicKeyAndChallenge setProvider(Provider provider)
		{
			return new JcaSignedPublicKeyAndChallenge(this.spkacSeq, new ProviderJcaJceHelper(provider));
		}

		public virtual PublicKey getPublicKey()
		{
			try
			{
				SubjectPublicKeyInfo subjectPublicKeyInfo = spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
				X509EncodedKeySpec xspec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());


				AlgorithmIdentifier keyAlg = subjectPublicKeyInfo.getAlgorithm();

				KeyFactory factory = helper.createKeyFactory(keyAlg.getAlgorithm().getId());

				return factory.generatePublic(xspec);
			}
			catch (Exception)
			{
				throw new InvalidKeyException("error encoding public key");
			}
		}
	}

}