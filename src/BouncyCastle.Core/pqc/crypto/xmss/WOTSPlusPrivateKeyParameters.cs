using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	/// <summary>
	/// WOTS+ private key.
	/// </summary>
	public sealed class WOTSPlusPrivateKeyParameters
	{

		private readonly byte[][] privateKey;

		public WOTSPlusPrivateKeyParameters(WOTSPlusParameters @params, byte[][] privateKey) : base()
		{
			if (@params == null)
			{
				throw new NullPointerException("params == null");
			}
			if (privateKey == null)
			{
				throw new NullPointerException("privateKey == null");
			}
			if (XMSSUtil.hasNullPointer(privateKey))
			{
				throw new NullPointerException("privateKey byte array == null");
			}
			if (privateKey.Length != @params.getLen())
			{
				throw new IllegalArgumentException("wrong privateKey format");
			}
			for (int i = 0; i < privateKey.Length; i++)
			{
				if (privateKey[i].Length != @params.getDigestSize())
				{
					throw new IllegalArgumentException("wrong privateKey format");
				}
			}
			this.privateKey = XMSSUtil.cloneArray(privateKey);
		}

		public byte[][] toByteArray()
		{
			return XMSSUtil.cloneArray(privateKey);
		}
	}

}