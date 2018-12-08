using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using OCSPRequest = org.bouncycastle.asn1.ocsp.OCSPRequest;
	using Request = org.bouncycastle.asn1.ocsp.Request;
	using Signature = org.bouncycastle.asn1.ocsp.Signature;
	using TBSRequest = org.bouncycastle.asn1.ocsp.TBSRequest;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;

	public class OCSPReqBuilder
	{
		private List list = new ArrayList();
		private GeneralName requestorName = null;
		private Extensions requestExtensions = null;

		public class RequestObject
		{
			private readonly OCSPReqBuilder outerInstance;

			internal CertificateID certId;
			internal Extensions extensions;

			public RequestObject(OCSPReqBuilder outerInstance, CertificateID certId, Extensions extensions)
			{
				this.outerInstance = outerInstance;
				this.certId = certId;
				this.extensions = extensions;
			}

			public virtual Request toRequest()
			{
				return new Request(certId.toASN1Primitive(), extensions);
			}
		}

		/// <summary>
		/// Add a request for the given CertificateID.
		/// </summary>
		/// <param name="certId"> certificate ID of interest </param>
		public virtual OCSPReqBuilder addRequest(CertificateID certId)
		{
			list.add(new RequestObject(this, certId, null));

			return this;
		}

		/// <summary>
		/// Add a request with extensions
		/// </summary>
		/// <param name="certId"> certificate ID of interest </param>
		/// <param name="singleRequestExtensions"> the extensions to attach to the request </param>
		public virtual OCSPReqBuilder addRequest(CertificateID certId, Extensions singleRequestExtensions)
		{
			list.add(new RequestObject(this, certId, singleRequestExtensions));

			return this;
		}

		/// <summary>
		/// Set the requestor name to the passed in X500Name
		/// </summary>
		/// <param name="requestorName"> an X500Name representing the requestor name. </param>
		public virtual OCSPReqBuilder setRequestorName(X500Name requestorName)
		{
			this.requestorName = new GeneralName(GeneralName.directoryName, requestorName);

			return this;
		}

		public virtual OCSPReqBuilder setRequestorName(GeneralName requestorName)
		{
			this.requestorName = requestorName;

			return this;
		}

		public virtual OCSPReqBuilder setRequestExtensions(Extensions requestExtensions)
		{
			this.requestExtensions = requestExtensions;

			return this;
		}

		private OCSPReq generateRequest(ContentSigner contentSigner, X509CertificateHolder[] chain)
		{
			Iterator it = list.iterator();

			ASN1EncodableVector requests = new ASN1EncodableVector();

			while (it.hasNext())
			{
				try
				{
					requests.add(((RequestObject)it.next()).toRequest());
				}
				catch (Exception e)
				{
					throw new OCSPException("exception creating Request", e);
				}
			}

			TBSRequest tbsReq = new TBSRequest(requestorName, new DERSequence(requests), requestExtensions);

			Signature signature = null;

			if (contentSigner != null)
			{
				if (requestorName == null)
				{
					throw new OCSPException("requestorName must be specified if request is signed.");
				}

				try
				{
					OutputStream sOut = contentSigner.getOutputStream();

					sOut.write(tbsReq.getEncoded(ASN1Encoding_Fields.DER));

					sOut.close();
				}
				catch (Exception e)
				{
					throw new OCSPException("exception processing TBSRequest: " + e, e);
				}

				DERBitString bitSig = new DERBitString(contentSigner.getSignature());

				AlgorithmIdentifier sigAlgId = contentSigner.getAlgorithmIdentifier();

				if (chain != null && chain.Length > 0)
				{
					ASN1EncodableVector v = new ASN1EncodableVector();

					for (int i = 0; i != chain.Length; i++)
					{
						v.add(chain[i].toASN1Structure());
					}

					signature = new Signature(sigAlgId, bitSig, new DERSequence(v));
				}
				else
				{
					signature = new Signature(sigAlgId, bitSig);
				}
			}

			return new OCSPReq(new OCSPRequest(tbsReq, signature));
		}

		/// <summary>
		/// Generate an unsigned request
		/// </summary>
		/// <returns> the OCSPReq </returns>
		/// <exception cref="org.bouncycastle.cert.ocsp.OCSPException"> </exception>
		public virtual OCSPReq build()
		{
			return generateRequest(null, null);
		}

		public virtual OCSPReq build(ContentSigner signer, X509CertificateHolder[] chain)
		{
			if (signer == null)
			{
				throw new IllegalArgumentException("no signer specified");
			}

			return generateRequest(signer, chain);
		}
	}

}