using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.parsers
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using Streams = org.bouncycastle.util.io.Streams;

	public class DHIESPublicKeyParser : KeyParser
	{
		private DHParameters dhParams;

		public DHIESPublicKeyParser(DHParameters dhParams)
		{
			this.dhParams = dhParams;
		}

		public virtual AsymmetricKeyParameter readKey(InputStream stream)
		{
			byte[] V = new byte[(dhParams.getP().bitLength() + 7) / 8];

			Streams.readFully(stream, V, 0, V.Length);

			return new DHPublicKeyParameters(new BigInteger(1, V), dhParams);
		}
	}

}