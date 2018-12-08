using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using RevokedInfo = org.bouncycastle.asn1.ocsp.RevokedInfo;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;

	/// <summary>
	/// wrapper for the RevokedInfo object
	/// </summary>
	public class RevokedStatus : CertificateStatus
	{
		internal RevokedInfo info;

		public RevokedStatus(RevokedInfo info)
		{
			this.info = info;
		}

		public RevokedStatus(DateTime revocationDate, int reason)
		{
			this.info = new RevokedInfo(new ASN1GeneralizedTime(revocationDate), CRLReason.lookup(reason));
		}

		public virtual DateTime getRevocationTime()
		{
			return OCSPUtils.extractDate(info.getRevocationTime());
		}

		public virtual bool hasRevocationReason()
		{
			return (info.getRevocationReason() != null);
		}

		/// <summary>
		/// return the revocation reason. Note: this field is optional, test for it
		/// with hasRevocationReason() first. </summary>
		/// <returns> the revocation reason value. </returns>
		/// <exception cref="IllegalStateException"> if a reason is asked for and none is avaliable </exception>
		public virtual int getRevocationReason()
		{
			if (info.getRevocationReason() == null)
			{
				throw new IllegalStateException("attempt to get a reason where none is available");
			}

			return info.getRevocationReason().getValue().intValue();
		}
	}

}