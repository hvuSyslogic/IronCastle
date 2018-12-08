using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1;

namespace org.bouncycastle.tsp
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using DLSequence = org.bouncycastle.asn1.DLSequence;
	using PKIFailureInfo = org.bouncycastle.asn1.cmp.PKIFailureInfo;
	using PKIFreeText = org.bouncycastle.asn1.cmp.PKIFreeText;
	using PKIStatus = org.bouncycastle.asn1.cmp.PKIStatus;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TimeStampResp = org.bouncycastle.asn1.tsp.TimeStampResp;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Base class for an RFC 3161 Time Stamp Response object.
	/// </summary>
	public class TimeStampResponse
	{
		internal TimeStampResp resp;
		internal TimeStampToken timeStampToken;

		public TimeStampResponse(TimeStampResp resp)
		{
			this.resp = resp;

			if (resp.getTimeStampToken() != null)
			{
				timeStampToken = new TimeStampToken(resp.getTimeStampToken());
			}
		}

		/// <summary>
		/// Create a TimeStampResponse from a byte array containing an ASN.1 encoding.
		/// </summary>
		/// <param name="resp"> the byte array containing the encoded response. </param>
		/// <exception cref="TSPException"> if the response is malformed. </exception>
		/// <exception cref="IOException"> if the byte array doesn't represent an ASN.1 encoding. </exception>
		public TimeStampResponse(byte[] resp) : this(new ByteArrayInputStream(resp))
		{
		}

		/// <summary>
		/// Create a TimeStampResponse from an input stream containing an ASN.1 encoding.
		/// </summary>
		/// <param name="in"> the input stream containing the encoded response. </param>
		/// <exception cref="TSPException"> if the response is malformed. </exception>
		/// <exception cref="IOException"> if the stream doesn't represent an ASN.1 encoding. </exception>
		public TimeStampResponse(InputStream @in) : this(readTimeStampResp(@in))
		{
		}

		public TimeStampResponse(DLSequence dlSequence)
		{
			try
			{
				resp = TimeStampResp.getInstance(dlSequence);
				timeStampToken = new TimeStampToken(ContentInfo.getInstance(dlSequence.getObjectAt(1)));
			}
			catch (IllegalArgumentException e)
			{
				throw new TSPException("malformed timestamp response: " + e, e);
			}
			catch (ClassCastException e)
			{
				throw new TSPException("malformed timestamp response: " + e, e);
			}
		}

		private static TimeStampResp readTimeStampResp(InputStream @in)
		{
			try
			{
				return TimeStampResp.getInstance((new ASN1InputStream(@in)).readObject());
			}
			catch (IllegalArgumentException e)
			{
				throw new TSPException("malformed timestamp response: " + e, e);
			}
			catch (ClassCastException e)
			{
				throw new TSPException("malformed timestamp response: " + e, e);
			}
		}

		public virtual int getStatus()
		{
			return resp.getStatus().getStatus().intValue();
		}

		public virtual string getStatusString()
		{
			if (resp.getStatus().getStatusString() != null)
			{
				StringBuffer statusStringBuf = new StringBuffer();
				PKIFreeText text = resp.getStatus().getStatusString();
				for (int i = 0; i != text.size(); i++)
				{
					statusStringBuf.append(text.getStringAt(i).getString());
				}
				return statusStringBuf.ToString();
			}
			else
			{
				return null;
			}
		}

		public virtual PKIFailureInfo getFailInfo()
		{
			if (resp.getStatus().getFailInfo() != null)
			{
				return new PKIFailureInfo(resp.getStatus().getFailInfo());
			}

			return null;
		}

		public virtual TimeStampToken getTimeStampToken()
		{
			return timeStampToken;
		}

		/// <summary>
		/// Check this response against to see if it a well formed response for 
		/// the passed in request. Validation will include checking the time stamp
		/// token if the response status is GRANTED or GRANTED_WITH_MODS.
		/// </summary>
		/// <param name="request"> the request to be checked against </param>
		/// <exception cref="TSPException"> if the request can not match this response. </exception>
		public virtual void validate(TimeStampRequest request)
		{
			TimeStampToken tok = this.getTimeStampToken();

			if (tok != null)
			{
				TimeStampTokenInfo tstInfo = tok.getTimeStampInfo();

				if (request.getNonce() != null && !request.getNonce().Equals(tstInfo.getNonce()))
				{
					throw new TSPValidationException("response contains wrong nonce value.");
				}

				if (this.getStatus() != PKIStatus.GRANTED && this.getStatus() != PKIStatus.GRANTED_WITH_MODS)
				{
					throw new TSPValidationException("time stamp token found in failed request.");
				}

				if (!Arrays.constantTimeAreEqual(request.getMessageImprintDigest(), tstInfo.getMessageImprintDigest()))
				{
					throw new TSPValidationException("response for different message imprint digest.");
				}

				if (!tstInfo.getMessageImprintAlgOID().Equals(request.getMessageImprintAlgOID()))
				{
					throw new TSPValidationException("response for different message imprint algorithm.");
				}

				Attribute scV1 = tok.getSignedAttributes().get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate);
				Attribute scV2 = tok.getSignedAttributes().get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2);

				if (scV1 == null && scV2 == null)
				{
					throw new TSPValidationException("no signing certificate attribute present.");
				}

				if (scV1 != null && scV2 != null)
				{
					/*
					 * RFC 5035 5.4. If both attributes exist in a single message,
					 * they are independently evaluated. 
					 */
				}

				if (request.getReqPolicy() != null && !request.getReqPolicy().Equals(tstInfo.getPolicy()))
				{
					throw new TSPValidationException("TSA policy wrong for request.");
				}
			}
			else if (this.getStatus() == PKIStatus.GRANTED || this.getStatus() == PKIStatus.GRANTED_WITH_MODS)
			{
				throw new TSPValidationException("no time stamp token found and one expected.");
			}
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return resp.getEncoded();
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded(string encoding)
		{
			if (ASN1Encoding_Fields.DL.Equals(encoding))
			{
				return (new DLSequence(new ASN1Encodable[] {resp.getStatus(), timeStampToken.toCMSSignedData().toASN1Structure()})).getEncoded(encoding);
			}
			return resp.getEncoded(encoding);
		}
	}
}