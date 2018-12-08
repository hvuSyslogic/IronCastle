namespace org.bouncycastle.@operator.bc
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using RSAEngine = org.bouncycastle.crypto.engines.RSAEngine;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public class BcRSAAsymmetricKeyUnwrapper : BcAsymmetricKeyUnwrapper
	{
		public BcRSAAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey) : base(encAlgId, privateKey)
		{
		}

		public override AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm)
		{
			return new PKCS1Encoding(new RSAEngine());
		}
	}

}