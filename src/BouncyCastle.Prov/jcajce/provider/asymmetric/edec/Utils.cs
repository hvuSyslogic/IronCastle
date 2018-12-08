namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using X25519PublicKeyParameters = org.bouncycastle.crypto.@params.X25519PublicKeyParameters;
	using X448PublicKeyParameters = org.bouncycastle.crypto.@params.X448PublicKeyParameters;
	using Fingerprint = org.bouncycastle.util.Fingerprint;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class Utils
	{
		internal static bool isValidPrefix(byte[] prefix, byte[] encoding)
		{
			if (encoding.Length < prefix.Length)
			{
				return !isValidPrefix(prefix, prefix);
			}

			int nonEqual = 0;

			for (int i = 0; i != prefix.Length; i++)
			{
				nonEqual |= (prefix[i] ^ encoding[i]);
			}

			return nonEqual == 0;
		}

		internal static string keyToString(string label, string algorithm, AsymmetricKeyParameter pubKey)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			byte[] keyBytes;
			if (pubKey is X448PublicKeyParameters)
			{
				keyBytes = ((X448PublicKeyParameters)pubKey).getEncoded();
			}
			else if (pubKey is Ed448PublicKeyParameters)
			{
				keyBytes = ((Ed448PublicKeyParameters)pubKey).getEncoded();
			}
			else if (pubKey is X25519PublicKeyParameters)
			{
				keyBytes = ((X25519PublicKeyParameters)pubKey).getEncoded();
			}
			else
			{
				keyBytes = ((Ed25519PublicKeyParameters)pubKey).getEncoded();
			}

			buf.append(algorithm).append(" ").append(label).append(" [").append(Utils.generateKeyFingerprint(keyBytes)).append("]").append(nl).append("    public data: ").append(Hex.toHexString(keyBytes)).append(nl);

			return buf.ToString();
		}

		private static string generateKeyFingerprint(byte[] keyBytes)
		{
			return (new Fingerprint(keyBytes)).ToString();
		}
	}

}