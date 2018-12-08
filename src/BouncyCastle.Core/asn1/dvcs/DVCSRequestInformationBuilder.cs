using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.dvcs
{

	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// <pre>
	///     DVCSRequestInformation ::= SEQUENCE  {
	///         version                      INTEGER DEFAULT 1 ,
	///         service                      ServiceType,
	///         nonce                        Nonce OPTIONAL,
	///         requestTime                  DVCSTime OPTIONAL,
	///         requester                    [0] GeneralNames OPTIONAL,
	///         requestPolicy                [1] PolicyInformation OPTIONAL,
	///         dvcs                         [2] GeneralNames OPTIONAL,
	///         dataLocations                [3] GeneralNames OPTIONAL,
	///         extensions                   [4] IMPLICIT Extensions OPTIONAL
	///     }
	/// </pre>
	/// </summary>
	public class DVCSRequestInformationBuilder
	{
		private int version = DEFAULT_VERSION;

		private readonly ServiceType service;
		private DVCSRequestInformation initialInfo;

		private BigInteger nonce;
		private DVCSTime requestTime;
		private GeneralNames requester;
		private PolicyInformation requestPolicy;
		private GeneralNames dvcs;
		private GeneralNames dataLocations;
		private Extensions extensions;

		private const int DEFAULT_VERSION = 1;
		private const int TAG_REQUESTER = 0;
		private const int TAG_REQUEST_POLICY = 1;
		private const int TAG_DVCS = 2;
		private const int TAG_DATA_LOCATIONS = 3;
		private const int TAG_EXTENSIONS = 4;

		public DVCSRequestInformationBuilder(ServiceType service)
		{
			this.service = service;
		}

		public DVCSRequestInformationBuilder(DVCSRequestInformation initialInfo)
		{
			this.initialInfo = initialInfo;
			this.service = initialInfo.getService();
			this.version = initialInfo.getVersion();
			this.nonce = initialInfo.getNonce();
			this.requestTime = initialInfo.getRequestTime();
			this.requestPolicy = initialInfo.getRequestPolicy();
			this.dvcs = initialInfo.getDVCS();
			this.dataLocations = initialInfo.getDataLocations();
		}

		public virtual DVCSRequestInformation build()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (version != DEFAULT_VERSION)
			{
				v.add(new ASN1Integer(version));
			}
			v.add(service);
			if (nonce != null)
			{
				v.add(new ASN1Integer(nonce));
			}
			if (requestTime != null)
			{
				v.add(requestTime);
			}

			int[] tags = new int[]{TAG_REQUESTER, TAG_REQUEST_POLICY, TAG_DVCS, TAG_DATA_LOCATIONS, TAG_EXTENSIONS};
			ASN1Encodable[] taggedObjects = new ASN1Encodable[]{requester, requestPolicy, dvcs, dataLocations, extensions};
			for (int i = 0; i < tags.Length; i++)
			{
				int tag = tags[i];
				ASN1Encodable taggedObject = taggedObjects[i];
				if (taggedObject != null)
				{
					v.add(new DERTaggedObject(false, tag, taggedObject));
				}
			}

			return DVCSRequestInformation.getInstance(new DERSequence(v));
		}

		public virtual void setVersion(int version)
		{
			if (initialInfo != null)
			{
				throw new IllegalStateException("cannot change version in existing DVCSRequestInformation");
			}

			this.version = version;
		}

		public virtual void setNonce(BigInteger nonce)
		{
			// RFC 3029, 9.1: The DVCS MAY modify the fields
			// 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure

			// RFC 3029, 9.1: The only modification
			// allowed to a 'nonce' is the inclusion of a new field if it was not
			// present, or to concatenate other data to the end (right) of an
			// existing value.
			if (initialInfo != null)
			{
				if (initialInfo.getNonce() == null)
				{
					this.nonce = nonce;
				}
				else
				{
					byte[] initialBytes = initialInfo.getNonce().toByteArray();
					byte[] newBytes = BigIntegers.asUnsignedByteArray(nonce);
					byte[] nonceBytes = new byte[initialBytes.Length + newBytes.Length];

					JavaSystem.arraycopy(initialBytes, 0, nonceBytes, 0, initialBytes.Length);
					JavaSystem.arraycopy(newBytes, 0, nonceBytes, initialBytes.Length, newBytes.Length);

					this.nonce = new BigInteger(nonceBytes);
				}
			}

			this.nonce = nonce;
		}

		public virtual void setRequestTime(DVCSTime requestTime)
		{
			if (initialInfo != null)
			{
				throw new IllegalStateException("cannot change request time in existing DVCSRequestInformation");
			}

			this.requestTime = requestTime;
		}

		public virtual void setRequester(GeneralName requester)
		{
			this.setRequester(new GeneralNames(requester));
		}

		public virtual void setRequester(GeneralNames requester)
		{
			// RFC 3029, 9.1: The DVCS MAY modify the fields
			// 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure

			this.requester = requester;
		}

		public virtual void setRequestPolicy(PolicyInformation requestPolicy)
		{
			if (initialInfo != null)
			{
				throw new IllegalStateException("cannot change request policy in existing DVCSRequestInformation");
			}

			this.requestPolicy = requestPolicy;
		}

		public virtual void setDVCS(GeneralName dvcs)
		{
			this.setDVCS(new GeneralNames(dvcs));
		}

		public virtual void setDVCS(GeneralNames dvcs)
		{
			// RFC 3029, 9.1: The DVCS MAY modify the fields
			// 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure

			this.dvcs = dvcs;
		}

		public virtual void setDataLocations(GeneralName dataLocation)
		{
			this.setDataLocations(new GeneralNames(dataLocation));
		}

		public virtual void setDataLocations(GeneralNames dataLocations)
		{
			// RFC 3029, 9.1: The DVCS MAY modify the fields
			// 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure

			this.dataLocations = dataLocations;
		}

		public virtual void setExtensions(Extensions extensions)
		{
			if (initialInfo != null)
			{
				throw new IllegalStateException("cannot change extensions in existing DVCSRequestInformation");
			}

			this.extensions = extensions;
		}
	}

}