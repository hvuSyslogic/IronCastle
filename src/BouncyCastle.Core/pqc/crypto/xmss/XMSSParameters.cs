using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	using Digest = org.bouncycastle.crypto.Digest;

	/// <summary>
	/// XMSS Parameters.
	/// </summary>
	public sealed class XMSSParameters
	{

		private readonly XMSSOid oid;
		private readonly WOTSPlus wotsPlus;
		//private final SecureRandom prng;
		private readonly int height;
		private readonly int k;

		/// <summary>
		/// XMSS Constructor...
		/// </summary>
		/// <param name="height"> Height of tree. </param>
		/// <param name="digest"> Digest to use. </param>
		public XMSSParameters(int height, Digest digest) : base()
		{
			if (height < 2)
			{
				throw new IllegalArgumentException("height must be >= 2");
			}
			if (digest == null)
			{
				throw new NullPointerException("digest == null");
			}

			wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
			this.height = height;
			this.k = determineMinK();
			oid = DefaultXMSSOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(), wotsPlus.getParams().getLen(), height);
			/*
			 * if (oid == null) { throw new InvalidParameterException(); }
			 */
		}

		private int determineMinK()
		{
			for (int k = 2; k <= height; k++)
			{
				if ((height - k) % 2 == 0)
				{
					return k;
				}
			}
			throw new IllegalStateException("should never happen...");
		}

		public Digest getDigest()
		{
			return wotsPlus.getParams().getDigest();
		}

		/// <summary>
		/// Getter digest size.
		/// </summary>
		/// <returns> Digest size. </returns>
		public int getDigestSize()
		{
			return wotsPlus.getParams().getDigestSize();
		}

		/// <summary>
		/// Getter Winternitz parameter.
		/// </summary>
		/// <returns> Winternitz parameter. </returns>
		public int getWinternitzParameter()
		{
			return wotsPlus.getParams().getWinternitzParameter();
		}

		/// <summary>
		/// Getter height.
		/// </summary>
		/// <returns> XMSS height. </returns>
		public int getHeight()
		{
			return height;
		}

		public WOTSPlus getWOTSPlus()
		{
			return wotsPlus;
		}

		public int getK()
		{
			return k;
		}
	}

}