using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	/// <summary>
	/// WOTS+ signature.
	/// </summary>
	public sealed class WOTSPlusSignature
	{

		private byte[][] signature;

		public WOTSPlusSignature(WOTSPlusParameters @params, byte[][] signature) : base()
		{
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			if (signature == null)
			{
				throw new NullPointerException("signature == null");
			}
			if (XMSSUtil.hasNullPointer(signature))
			{
				throw new NullPointerException("signature byte array == null");
			}
			if (signature.Length != @params.getLen())
			{
				throw new IllegalArgumentException("wrong signature size");
			}
			for (int i = 0; i < signature.Length; i++)
			{
				if (signature[i].Length != @params.getDigestSize())
				{
					throw new IllegalArgumentException("wrong signature format");
				}
			}
			this.signature = XMSSUtil.cloneArray(signature);
		}

		public byte[][] toByteArray()
		{
			return XMSSUtil.cloneArray(signature);
		}
	}

}