using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ResponseData = org.bouncycastle.asn1.ocsp.ResponseData;
	using SingleResponse = org.bouncycastle.asn1.ocsp.SingleResponse;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	public class RespData
	{
		private ResponseData data;

		public RespData(ResponseData data)
		{
			this.data = data;
		}

		public virtual int getVersion()
		{
			return data.getVersion().getValue().intValue() + 1;
		}

		public virtual RespID getResponderId()
		{
			return new RespID(data.getResponderID());
		}

		public virtual DateTime getProducedAt()
		{
			return OCSPUtils.extractDate(data.getProducedAt());
		}

		public virtual SingleResp[] getResponses()
		{
			ASN1Sequence s = data.getResponses();
			SingleResp[] rs = new SingleResp[s.size()];

			for (int i = 0; i != rs.Length; i++)
			{
				rs[i] = new SingleResp(SingleResponse.getInstance(s.getObjectAt(i)));
			}

			return rs;
		}

		public virtual Extensions getResponseExtensions()
		{
			return data.getResponseExtensions();
		}
	}

}