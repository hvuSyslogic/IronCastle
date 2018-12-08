using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CertStatus = org.bouncycastle.asn1.ocsp.CertStatus;
	using RevokedInfo = org.bouncycastle.asn1.ocsp.RevokedInfo;
	using SingleResponse = org.bouncycastle.asn1.ocsp.SingleResponse;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	public class SingleResp
	{
		private SingleResponse resp;
		private Extensions extensions;

		public SingleResp(SingleResponse resp)
		{
			this.resp = resp;
			this.extensions = resp.getSingleExtensions();
		}

		public virtual CertificateID getCertID()
		{
			return new CertificateID(resp.getCertID());
		}

		/// <summary>
		/// Return the status object for the response - null indicates good.
		/// </summary>
		/// <returns> the status object for the response, null if it is good. </returns>
		public virtual CertificateStatus getCertStatus()
		{
			CertStatus s = resp.getCertStatus();

			if (s.getTagNo() == 0)
			{
				return null; // good
			}
			else if (s.getTagNo() == 1)
			{
				return new RevokedStatus(RevokedInfo.getInstance(s.getStatus()));
			}

			return new UnknownStatus();
		}

		public virtual DateTime getThisUpdate()
		{
			return OCSPUtils.extractDate(resp.getThisUpdate());
		}

		/// <summary>
		/// return the NextUpdate value - note: this is an optional field so may
		/// be returned as null.
		/// </summary>
		/// <returns> nextUpdate, or null if not present. </returns>
		public virtual DateTime getNextUpdate()
		{
			if (resp.getNextUpdate() == null)
			{
				return null;
			}

			return OCSPUtils.extractDate(resp.getNextUpdate());
		}

		public virtual bool hasExtensions()
		{
			return extensions != null;
		}

		public virtual Extension getExtension(ASN1ObjectIdentifier oid)
		{
			if (extensions != null)
			{
				return extensions.getExtension(oid);
			}

			return null;
		}

		public virtual List getExtensionOIDs()
		{
			return OCSPUtils.getExtensionOIDs(extensions);
		}

		public virtual Set getCriticalExtensionOIDs()
		{
			return OCSPUtils.getCriticalExtensionOIDs(extensions);
		}

		public virtual Set getNonCriticalExtensionOIDs()
		{
			return OCSPUtils.getNonCriticalExtensionOIDs(extensions);
		}
	}

}