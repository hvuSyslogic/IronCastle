namespace org.bouncycastle.@operator.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using RSAEngine = org.bouncycastle.crypto.engines.RSAEngine;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using PublicKeyFactory = org.bouncycastle.crypto.util.PublicKeyFactory;

	public class BcRSAAsymmetricKeyWrapper : BcAsymmetricKeyWrapper
	{
		public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey) : base(encAlgId, publicKey)
		{
		}

		public BcRSAAsymmetricKeyWrapper(AlgorithmIdentifier encAlgId, SubjectPublicKeyInfo publicKeyInfo) : base(encAlgId, PublicKeyFactory.createKey(publicKeyInfo))
		{
		}

		public override AsymmetricBlockCipher createAsymmetricWrapper(ASN1ObjectIdentifier algorithm)
		{
			return new PKCS1Encoding(new RSAEngine());
		}
	}

}