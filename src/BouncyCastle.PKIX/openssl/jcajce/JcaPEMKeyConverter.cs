using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.openssl.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaPEMKeyConverter
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();

		private static readonly Map algorithms = new HashMap();

		static JcaPEMKeyConverter()
		{
			algorithms.put(X9ObjectIdentifiers_Fields.id_ecPublicKey, "ECDSA");
			algorithms.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			algorithms.put(X9ObjectIdentifiers_Fields.id_dsa, "DSA");
		}

		public virtual JcaPEMKeyConverter setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		public virtual JcaPEMKeyConverter setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual KeyPair getKeyPair(PEMKeyPair keyPair)
		{
			try
			{
				KeyFactory keyFactory = getKeyFactory(keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm());

				return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublicKeyInfo().getEncoded())), keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivateKeyInfo().getEncoded())));
			}
			catch (Exception e)
			{
				throw new PEMException("unable to convert key pair: " + e.Message, e);
			}
		}

		public virtual PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
		{
			try
			{
				KeyFactory keyFactory = getKeyFactory(publicKeyInfo.getAlgorithm());

				return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
			}
			catch (Exception e)
			{
				throw new PEMException("unable to convert key pair: " + e.Message, e);
			}
		}

		public virtual PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
		{
			try
			{
				KeyFactory keyFactory = getKeyFactory(privateKeyInfo.getPrivateKeyAlgorithm());

				return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
			}
			catch (Exception e)
			{
				throw new PEMException("unable to convert key pair: " + e.Message, e);
			}
		}

		private KeyFactory getKeyFactory(AlgorithmIdentifier algId)
		{
			ASN1ObjectIdentifier algorithm = algId.getAlgorithm();

			string algName = (string)algorithms.get(algorithm);

			if (string.ReferenceEquals(algName, null))
			{
				algName = algorithm.getId();
			}

			try
			{
				return helper.createKeyFactory(algName);
			}
			catch (NoSuchAlgorithmException e)
			{
				if (algName.Equals("ECDSA"))
				{
					return helper.createKeyFactory("EC"); // try a fall back
				}

				throw e;
			}
		}
	}

}