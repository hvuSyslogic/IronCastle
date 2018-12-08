using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERGeneralizedTime = org.bouncycastle.asn1.DERGeneralizedTime;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using BasicOCSPResponse = org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
	using CertStatus = org.bouncycastle.asn1.ocsp.CertStatus;
	using ResponseData = org.bouncycastle.asn1.ocsp.ResponseData;
	using RevokedInfo = org.bouncycastle.asn1.ocsp.RevokedInfo;
	using SingleResponse = org.bouncycastle.asn1.ocsp.SingleResponse;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	/// <summary>
	/// Generator for basic OCSP response objects.
	/// </summary>
	public class BasicOCSPRespBuilder
	{
		private List list = new ArrayList();
		private Extensions responseExtensions = null;
		private RespID responderID;

		public class ResponseObject
		{
			private readonly BasicOCSPRespBuilder outerInstance;

			internal CertificateID certId;
			internal CertStatus certStatus;
			internal ASN1GeneralizedTime thisUpdate;
			internal ASN1GeneralizedTime nextUpdate;
			internal Extensions extensions;

			public ResponseObject(BasicOCSPRespBuilder outerInstance, CertificateID certId, CertificateStatus certStatus, DateTime thisUpdate, DateTime nextUpdate, Extensions extensions)
			{
				this.outerInstance = outerInstance;
				this.certId = certId;

				if (certStatus == null)
				{
					this.certStatus = new CertStatus();
				}
				else if (certStatus is UnknownStatus)
				{
					this.certStatus = new CertStatus(2, DERNull.INSTANCE);
				}
				else
				{
					RevokedStatus rs = (RevokedStatus)certStatus;

					if (rs.hasRevocationReason())
					{
						this.certStatus = new CertStatus(new RevokedInfo(new ASN1GeneralizedTime(rs.getRevocationTime()), CRLReason.lookup(rs.getRevocationReason())));
					}
					else
					{
						this.certStatus = new CertStatus(new RevokedInfo(new ASN1GeneralizedTime(rs.getRevocationTime()), null));
					}
				}

				this.thisUpdate = new DERGeneralizedTime(thisUpdate);

				if (nextUpdate != null)
				{
					this.nextUpdate = new DERGeneralizedTime(nextUpdate);
				}
				else
				{
					this.nextUpdate = null;
				}

				this.extensions = extensions;
			}

			public virtual SingleResponse toResponse()
			{
				return new SingleResponse(certId.toASN1Primitive(), certStatus, thisUpdate, nextUpdate, extensions);
			}
		}

		/// <summary>
		/// basic constructor
		/// </summary>
		public BasicOCSPRespBuilder(RespID responderID)
		{
			this.responderID = responderID;
		}

		/// <summary>
		/// construct with the responderID to be the SHA-1 keyHash of the passed in public key.
		/// </summary>
		/// <param name="key"> the key info of the responder public key. </param>
		/// <param name="digCalc">  a SHA-1 digest calculator </param>
		public BasicOCSPRespBuilder(SubjectPublicKeyInfo key, DigestCalculator digCalc)
		{
			this.responderID = new RespID(key, digCalc);
		}

		/// <summary>
		/// Add a response for a particular Certificate ID.
		/// </summary>
		/// <param name="certID"> certificate ID details </param>
		/// <param name="certStatus"> status of the certificate - null if okay </param>
		public virtual BasicOCSPRespBuilder addResponse(CertificateID certID, CertificateStatus certStatus)
		{
			this.addResponse(certID, certStatus, DateTime.Now, null, null);

			return this;
		}

		/// <summary>
		/// Add a response for a particular Certificate ID.
		/// </summary>
		/// <param name="certID"> certificate ID details </param>
		/// <param name="certStatus"> status of the certificate - null if okay </param>
		/// <param name="singleExtensions"> optional extensions </param>
		public virtual BasicOCSPRespBuilder addResponse(CertificateID certID, CertificateStatus certStatus, Extensions singleExtensions)
		{
			this.addResponse(certID, certStatus, DateTime.Now, null, singleExtensions);

			return this;
		}

		/// <summary>
		/// Add a response for a particular Certificate ID.
		/// </summary>
		/// <param name="certID"> certificate ID details </param>
		/// <param name="nextUpdate"> date when next update should be requested </param>
		/// <param name="certStatus"> status of the certificate - null if okay </param>
		/// <param name="singleExtensions"> optional extensions </param>
		public virtual BasicOCSPRespBuilder addResponse(CertificateID certID, CertificateStatus certStatus, DateTime nextUpdate, Extensions singleExtensions)
		{
			this.addResponse(certID, certStatus, DateTime.Now, nextUpdate, singleExtensions);

			return this;
		}

		/// <summary>
		/// Add a response for a particular Certificate ID.
		/// </summary>
		/// <param name="certID"> certificate ID details </param>
		/// <param name="thisUpdate"> date this response was valid on </param>
		/// <param name="nextUpdate"> date when next update should be requested </param>
		/// <param name="certStatus"> status of the certificate - null if okay </param>
		public virtual BasicOCSPRespBuilder addResponse(CertificateID certID, CertificateStatus certStatus, DateTime thisUpdate, DateTime nextUpdate)
		{
			this.addResponse(certID, certStatus, thisUpdate, nextUpdate, null);

			return this;
		}

		/// <summary>
		/// Add a response for a particular Certificate ID.
		/// </summary>
		/// <param name="certID"> certificate ID details </param>
		/// <param name="thisUpdate"> date this response was valid on </param>
		/// <param name="nextUpdate"> date when next update should be requested </param>
		/// <param name="certStatus"> status of the certificate - null if okay </param>
		/// <param name="singleExtensions"> optional extensions </param>
		public virtual BasicOCSPRespBuilder addResponse(CertificateID certID, CertificateStatus certStatus, DateTime thisUpdate, DateTime nextUpdate, Extensions singleExtensions)
		{
			list.add(new ResponseObject(this, certID, certStatus, thisUpdate, nextUpdate, singleExtensions));

			return this;
		}

		/// <summary>
		/// Set the extensions for the response.
		/// </summary>
		/// <param name="responseExtensions"> the extension object to carry. </param>
		public virtual BasicOCSPRespBuilder setResponseExtensions(Extensions responseExtensions)
		{
			this.responseExtensions = responseExtensions;

			return this;
		}

		public virtual BasicOCSPResp build(ContentSigner signer, X509CertificateHolder[] chain, DateTime producedAt)
		{
			Iterator it = list.iterator();

			ASN1EncodableVector responses = new ASN1EncodableVector();

			while (it.hasNext())
			{
				try
				{
					responses.add(((ResponseObject)it.next()).toResponse());
				}
				catch (Exception e)
				{
					throw new OCSPException("exception creating Request", e);
				}
			}

			ResponseData tbsResp = new ResponseData(responderID.toASN1Primitive(), new ASN1GeneralizedTime(producedAt), new DERSequence(responses), responseExtensions);
			DERBitString bitSig;

			try
			{
				OutputStream sigOut = signer.getOutputStream();

				sigOut.write(tbsResp.getEncoded(ASN1Encoding_Fields.DER));
				sigOut.close();

				bitSig = new DERBitString(signer.getSignature());
			}
			catch (Exception e)
			{
				throw new OCSPException("exception processing TBSRequest: " + e.Message, e);
			}

			AlgorithmIdentifier sigAlgId = signer.getAlgorithmIdentifier();

			DERSequence chainSeq = null;
			if (chain != null && chain.Length > 0)
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				for (int i = 0; i != chain.Length; i++)
				{
					v.add(chain[i].toASN1Structure());
				}

				chainSeq = new DERSequence(v);
			}

			return new BasicOCSPResp(new BasicOCSPResponse(tbsResp, sigAlgId, bitSig, chainSeq));
		}
	}

}