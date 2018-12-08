namespace org.bouncycastle.pqc.crypto.newhope
{
	using ChaChaEngine = org.bouncycastle.crypto.engines.ChaChaEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

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