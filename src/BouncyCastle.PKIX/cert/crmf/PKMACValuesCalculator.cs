namespace org.bouncycastle.cert.crmf
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface PKMACValuesCalculator
	{
		void setup(AlgorithmIdentifier digestAlg, AlgorithmIdentifier macAlg);

		byte[] calculateDigest(byte[] data);

		byte[] calculateMac(byte[] pwd, byte[] data);
	}

}