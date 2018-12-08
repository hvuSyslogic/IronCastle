using System;

namespace org.bouncycastle.jce.provider
{

	public class CertStatus
	{
		public const int UNREVOKED = 11;

		public const int UNDETERMINED = 12;

		internal int certStatus = UNREVOKED;

		internal DateTime revocationDate = null;

		/// <returns> Returns the revocationDate. </returns>
		public virtual DateTime getRevocationDate()
		{
			return revocationDate;
		}

		/// <param name="revocationDate"> The revocationDate to set. </param>
		public virtual void setRevocationDate(DateTime revocationDate)
		{
			this.revocationDate = revocationDate;
		}

		/// <returns> Returns the certStatus. </returns>
		public virtual int getCertStatus()
		{
			return certStatus;
		}

		/// <param name="certStatus"> The certStatus to set. </param>
		public virtual void setCertStatus(int certStatus)
		{
			this.certStatus = certStatus;
		}
	}

}