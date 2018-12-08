using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	using Digest = org.bouncycastle.crypto.Digest;

	/// <summary>
	/// XMSS^MT Parameters.
	/// </summary>
	public sealed class XMSSMTParameters
	{

		private readonly XMSSOid oid;
		private readonly XMSSParameters xmssParams;
		private readonly int height;
		private readonly int layers;

		/// <summary>
		/// XMSSMT constructor...
		/// </summary>
		/// <param name="height"> Height of tree. </param>
		/// <param name="layers"> Amount of layers. </param>
		/// <param name="digest"> Digest to use. </param>
		public XMSSMTParameters(int height, int layers, Digest digest) : base()
		{
			this.height = height;
			this.layers = layers;
			this.xmssParams = new XMSSParameters(xmssTreeHeight(height, layers), digest);
			oid = DefaultXMSSMTOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(), getLen(), getHeight(), layers);
			/*
			 * if (oid == null) { throw new InvalidParameterException(); }
			 */
		}

		private static int xmssTreeHeight(int height, int layers)
		{
			if (height < 2)
			{
				throw new IllegalArgumentException("totalHeight must be > 1");
			}
			if (height % layers != 0)
			{
				throw new IllegalArgumentException("layers must divide totalHeight without remainder");
			}
			if (height / layers == 1)
			{
				throw new IllegalArgumentException("height / layers must be greater than 1");
			}
			return height / layers;
		}

		/// <summary>
		/// Getter height.
		/// </summary>
		/// <returns> XMSSMT height. </returns>
		public int getHeight()
		{
			return height;
		}

		/// <summary>
		/// Getter layers.
		/// </summary>
		/// <returns> XMSSMT layers. </returns>
		public int getLayers()
		{
			return layers;
		}

		public XMSSParameters getXMSSParameters()
		{
			return xmssParams;
		}

		public WOTSPlus getWOTSPlus()
		{
			return xmssParams.getWOTSPlus();
		}

		public Digest getDigest()
		{
			return xmssParams.getDigest();
		}

		/// <summary>
		/// Getter digest size.
		/// </summary>
		/// <returns> Digest size. </returns>
		public int getDigestSize()
		{
			return xmssParams.getDigestSize();
		}

		/// <summary>
		/// Getter Winternitz parameter.
		/// </summary>
		/// <returns> Winternitz parameter. </returns>
		public int getWinternitzParameter()
		{
			return xmssParams.getWinternitzParameter();
		}

		public int getLen()
		{
			return xmssParams.getWOTSPlus().getParams().getLen();
		}
	}

}