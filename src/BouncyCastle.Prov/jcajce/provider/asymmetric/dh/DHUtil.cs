namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{

	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Fingerprint = org.bouncycastle.util.Fingerprint;
	using Strings = org.bouncycastle.util.Strings;

	public class DHUtil
	{
		internal static string privateKeyToString(string algorithm, BigInteger x, DHParameters dhParams)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			BigInteger y = dhParams.getG().modPow(x, dhParams.getP());

			buf.append(algorithm);
			buf.append(" Private Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
			buf.append("              Y: ").append(y.ToString(16)).append(nl);

			return buf.ToString();
		}

		internal static string publicKeyToString(string algorithm, BigInteger y, DHParameters dhParams)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append(algorithm);
			buf.append(" Public Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
			buf.append("             Y: ").append(y.ToString(16)).append(nl);

			return buf.ToString();
		}

		private static string generateKeyFingerprint(BigInteger y, DHParameters dhParams)
		{
				return (new Fingerprint(Arrays.concatenate(y.toByteArray(), dhParams.getP().toByteArray(), dhParams.getG().toByteArray()))).ToString();
		}
	}

}