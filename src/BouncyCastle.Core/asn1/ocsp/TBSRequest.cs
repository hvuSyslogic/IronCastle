using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.ocsp
{
			
	public class TBSRequest : ASN1Object
	{
		private static readonly ASN1Integer V1 = new ASN1Integer(0);

		internal ASN1Integer version;
		internal GeneralName requestorName;
		internal ASN1Sequence requestList;
		internal Extensions requestExtensions;

		internal bool versionSet;

		/// @deprecated use method taking Extensions 
		/// <param name="requestorName"> </param>
		/// <param name="requestList"> </param>
		/// <param name="requestExtensions"> </param>
		public TBSRequest(GeneralName requestorName, ASN1Sequence requestList, X509Extensions requestExtensions)
		{
			this.version = V1;
			this.requestorName = requestorName;
			this.requestList = requestList;
			this.requestExtensions = Extensions.getInstance(requestExtensions);
		}

		public TBSRequest(GeneralName requestorName, ASN1Sequence requestList, Extensions requestExtensions)
		{
			this.version = V1;
			this.requestorName = requestorName;
			this.requestList = requestList;
			this.requestExtensions = requestExtensions;
		}

		private TBSRequest(ASN1Sequence seq)
		{
			int index = 0;

			if (seq.getObjectAt(0) is ASN1TaggedObject)
			{
				ASN1TaggedObject o = (ASN1TaggedObject)seq.getObjectAt(0);

				if (o.getTagNo() == 0)
				{
					versionSet = true;
					version = ASN1Integer.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
					index++;
				}
				else
				{
					version = V1;
				}
			}
			else
			{
				version = V1;
			}

			if (seq.getObjectAt(index) is ASN1TaggedObject)
			{
				requestorName = GeneralName.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
			}

			requestList = (ASN1Sequence)seq.getObjectAt(index++);

			if (seq.size() == (index + 1))
			{
				requestExtensions = Extensions.getInstance((ASN1TaggedObject)seq.getObjectAt(index), true);
			}
		}

		public static TBSRequest getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static TBSRequest getInstance(object obj)
		{
			if (obj is TBSRequest)
			{
				return (TBSRequest)obj;
			}
			else if (obj != null)
			{
				return new TBSRequest(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual GeneralName getRequestorName()
		{
			return requestorName;
		}

		public virtual ASN1Sequence getRequestList()
		{
			return requestList;
		}

		public virtual Extensions getRequestExtensions()
		{
			return requestExtensions;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// TBSRequest      ::=     SEQUENCE {
		///     version             [0]     EXPLICIT Version DEFAULT v1,
		///     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
		///     requestList                 SEQUENCE OF Request,
		///     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			//
			// if default don't include - unless explicitly provided. Not strictly correct
			// but required for some requests
			//
			if (!version.Equals(V1) || versionSet)
			{
				v.add(new DERTaggedObject(true, 0, version));
			}

			if (requestorName != null)
			{
				v.add(new DERTaggedObject(true, 1, requestorName));
			}

			v.add(requestList);

			if (requestExtensions != null)
			{
				v.add(new DERTaggedObject(true, 2, requestExtensions));
			}

			return new DERSequence(v);
		}
	}

}