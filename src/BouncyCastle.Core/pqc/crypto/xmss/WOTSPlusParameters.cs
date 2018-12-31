using System;
using org.bouncycastle.crypto;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
	
	/// <summary>
	/// WOTS+ Parameters.
	/// </summary>
	public sealed class WOTSPlusParameters
	{

		/// <summary>
		/// OID.
		/// </summary>
		private readonly XMSSOid oid;
		/// <summary>
		/// Digest used in WOTS+.
		/// </summary>
		private readonly Digest digest;
		/// <summary>
		/// The message digest size.
		/// </summary>
		private readonly int digestSize;
		/// <summary>
		/// The Winternitz parameter (currently fixed to 16).
		/// </summary>
		private readonly int winternitzParameter;
		/// <summary>
		/// The number of n-byte string elements in a WOTS+ secret key, public key,
		/// and signature.
		/// </summary>
		private readonly int len;
		/// <summary>
		/// len1.
		/// </summary>
		private readonly int len1;
		/// <summary>
		/// len2.
		/// </summary>
		private readonly int len2;

		/// <summary>
		/// Constructor...
		/// </summary>
		/// <param name="digest"> The digest used for WOTS+. </param>
		public WOTSPlusParameters(Digest digest) : base()
		{
			if (digest == null)
			{
				throw new NullPointerException("digest == null");
			}
			this.digest = digest;
			digestSize = XMSSUtil.getDigestSize(digest);
			winternitzParameter = 16;
			len1 = (int)Math.Ceiling((double)(8 * digestSize) / XMSSUtil.log2(winternitzParameter));
			len2 = (int)Math.Floor(XMSSUtil.log2(len1 * (winternitzParameter - 1)) / (float)XMSSUtil.log2(winternitzParameter)) + 1;
			len = len1 + len2;
			oid = WOTSPlusOid.lookup(digest.getAlgorithmName(), digestSize, winternitzParameter, len);
			if (oid == null)
			{
				throw new IllegalArgumentException("cannot find OID for digest algorithm: " + digest.getAlgorithmName());
			}
		}

		/// <summary>
		/// Getter OID.
		/// </summary>
		/// <returns> WOTS+ OID. </returns>
		public XMSSOid getOid()
		{
			return oid;
		}

		/// <summary>
		/// Getter digest.
		/// </summary>
		/// <returns> digest. </returns>
		public Digest getDigest()
		{
			return digest;
		}

		/// <summary>
		/// Getter digestSize.
		/// </summary>
		/// <returns> digestSize. </returns>
		public int getDigestSize()
		{
			return digestSize;
		}

		/// <summary>
		/// Getter WinternitzParameter.
		/// </summary>
		/// <returns> winternitzParameter. </returns>
		public int getWinternitzParameter()
		{
			return winternitzParameter;
		}

		/// <summary>
		/// Getter len.
		/// </summary>
		/// <returns> len. </returns>
		public int getLen()
		{
			return len;
		}

		/// <summary>
		/// Getter len1.
		/// </summary>
		/// <returns> len1. </returns>
		public int getLen1()
		{
			return len1;
		}

		/// <summary>
		/// Getter len2.
		/// </summary>
		/// <returns> len2. </returns>
		public int getLen2()
		{
			return len2;
		}
	}

}