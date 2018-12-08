namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using GOST3410Parameters = org.bouncycastle.crypto.@params.GOST3410Parameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Fingerprint = org.bouncycastle.util.Fingerprint;
	using Strings = org.bouncycastle.util.Strings;

	public class GOSTUtil
	{
		internal static string privateKeyToString(string algorithm, BigInteger x, GOST3410Parameters gostParams)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			BigInteger y = gostParams.getA().modPow(x, gostParams.getP());

			buf.append(algorithm);
			buf.append(" Private Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
			buf.append("                  Y: ").append(y.ToString(16)).append(nl);

			return buf.ToString();
		}

		internal static string publicKeyToString(string algorithm, BigInteger y, GOST3410Parameters gostParams)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append(algorithm);
			buf.append(" Public Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
			buf.append("                 Y: ").append(y.ToString(16)).append(nl);

			return buf.ToString();
		}

		private static string generateKeyFingerprint(BigInteger y, GOST3410Parameters dhParams)
		{
				return (new Fingerprint(Arrays.concatenate(y.toByteArray(), dhParams.getP().toByteArray(), dhParams.getA().toByteArray()))).ToString();
		}
	}

}