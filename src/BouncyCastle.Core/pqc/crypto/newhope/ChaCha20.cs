using org.bouncycastle.crypto.engines;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.pqc.crypto.newhope
{
			
	public class ChaCha20
	{
		internal static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len)
		{
			ChaChaEngine e = new ChaChaEngine(20);
			e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
			e.processBytes(buf, off, len, buf, off);
		}
	}

}