namespace org.bouncycastle.cert.crmf
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;

	public interface ValueDecryptorGenerator
	{
		InputDecryptor getValueDecryptor(AlgorithmIdentifier keyAlg, AlgorithmIdentifier symmAlg, byte[] encKey);
	}

}