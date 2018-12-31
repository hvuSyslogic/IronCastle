using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.parsers
{

				
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