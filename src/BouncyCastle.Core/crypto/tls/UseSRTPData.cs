using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 5764 4.1.1
	/// </summary>
	public class UseSRTPData
	{
		protected internal int[] protectionProfiles;
		protected internal byte[] mki;

		/// <param name="protectionProfiles"> see <seealso cref="SRTPProtectionProfile"/> for valid constants. </param>
		/// <param name="mki">                valid lengths from 0 to 255. </param>
		public UseSRTPData(int[] protectionProfiles, byte[] mki)
		{
			if (protectionProfiles == null || protectionProfiles.Length < 1 || protectionProfiles.Length >= (1 << 15))
			{
				throw new IllegalArgumentException("'protectionProfiles' must have length from 1 to (2^15 - 1)");
			}

			if (mki == null)
			{
				mki = TlsUtils.EMPTY_BYTES;
			}
			else if (mki.Length > 255)
			{
				throw new IllegalArgumentException("'mki' cannot be longer than 255 bytes");
			}

			this.protectionProfiles = protectionProfiles;
			this.mki = mki;
		}

		/// <returns> see <seealso cref="SRTPProtectionProfile"/> for valid constants. </returns>
		public virtual int[] getProtectionProfiles()
		{
			return protectionProfiles;
		}

		/// <returns> valid lengths from 0 to 255. </returns>
		public virtual byte[] getMki()
		{
			return mki;
		}
	}

}