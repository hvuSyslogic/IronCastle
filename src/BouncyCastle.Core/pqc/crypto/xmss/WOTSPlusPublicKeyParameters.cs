using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	/// <summary>
	/// WOTS+ public key.
	/// </summary>
	public sealed class WOTSPlusPublicKeyParameters
	{

		private readonly byte[][] publicKey;

		public WOTSPlusPublicKeyParameters(WOTSPlusParameters @params, byte[][] publicKey) : base()
		{
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			if (publicKey == null)
			{
				throw new NullPointerException("publicKey == null");
			}
			if (XMSSUtil.hasNullPointer(publicKey))
			{
				throw new NullPointerException("publicKey byte array == null");
			}
			if (publicKey.Length != @params.getLen())
			{
				throw new IllegalArgumentException("wrong publicKey size");
			}
			for (int i = 0; i < publicKey.Length; i++)
			{
				if (publicKey[i].Length != @params.getDigestSize())
				{
					throw new IllegalArgumentException("wrong publicKey format");
				}
			}
			this.publicKey = XMSSUtil.cloneArray(publicKey);
		}

		public byte[][] toByteArray()
		{
			return XMSSUtil.cloneArray(publicKey);
		}
	}

}