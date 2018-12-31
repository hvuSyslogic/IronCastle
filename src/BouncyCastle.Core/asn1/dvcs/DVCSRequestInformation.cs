using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.dvcs
{

			
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

	public class DVCSRequestInformation : ASN1Object
	{
		private int version = DEFAULT_VERSION;
		private ServiceType service;
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

		private DVCSRequestInformation(ASN1Sequence seq)
		{
			int i = 0;

			if (seq.getObjectAt(0) is ASN1Integer)
			{
				ASN1Integer encVersion = ASN1Integer.getInstance(seq.getObjectAt(i++));
				this.version = encVersion.getValue().intValue();
			}
			else
			{
				this.version = 1;
			}

			this.service = ServiceType.getInstance(seq.getObjectAt(i++));

			while (i < seq.size())
			{
				ASN1Encodable x = seq.getObjectAt(i);

				if (x is ASN1Integer)
				{
					this.nonce = ASN1Integer.getInstance(x).getValue();
				}
				else if (x is ASN1GeneralizedTime)
				{
					this.requestTime = DVCSTime.getInstance(x);
				}
				else if (x is ASN1TaggedObject)
				{
					ASN1TaggedObject t = ASN1TaggedObject.getInstance(x);
					int tagNo = t.getTagNo();

					switch (tagNo)
					{
					case TAG_REQUESTER:
						this.requester = GeneralNames.getInstance(t, false);
						break;
					case TAG_REQUEST_POLICY:
						this.requestPolicy = PolicyInformation.getInstance(ASN1Sequence.getInstance(t, false));
						break;
					case TAG_DVCS:
						this.dvcs = GeneralNames.getInstance(t, false);
						break;
					case TAG_DATA_LOCATIONS:
						this.dataLocations = GeneralNames.getInstance(t, false);
						break;
					case TAG_EXTENSIONS:
						this.extensions = Extensions.getInstance(t, false);
						break;
					default:
						throw new IllegalArgumentException("unknown tag number encountered: " + tagNo);
					}
				}
				else
				{
					this.requestTime = DVCSTime.getInstance(x);
				}

				i++;
			}
		}

		public static DVCSRequestInformation getInstance(object obj)
		{
			if (obj is DVCSRequestInformation)
			{
				return (DVCSRequestInformation)obj;
			}
			else if (obj != null)
			{
				return new DVCSRequestInformation(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static DVCSRequestInformation getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
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

			return new DERSequence(v);
		}

		public override string ToString()
		{

			StringBuffer s = new StringBuffer();

			s.append("DVCSRequestInformation {\n");

			if (version != DEFAULT_VERSION)
			{
				s.append("version: " + version + "\n");
			}
			s.append("service: " + service + "\n");
			if (nonce != null)
			{
				s.append("nonce: " + nonce + "\n");
			}
			if (requestTime != null)
			{
				s.append("requestTime: " + requestTime + "\n");
			}
			if (requester != null)
			{
				s.append("requester: " + requester + "\n");
			}
			if (requestPolicy != null)
			{
				s.append("requestPolicy: " + requestPolicy + "\n");
			}
			if (dvcs != null)
			{
				s.append("dvcs: " + dvcs + "\n");
			}
			if (dataLocations != null)
			{
				s.append("dataLocations: " + dataLocations + "\n");
			}
			if (extensions != null)
			{
				s.append("extensions: " + extensions + "\n");
			}

			s.append("}\n");
			return s.ToString();
		}

		public virtual int getVersion()
		{
			return version;
		}

		public virtual ServiceType getService()
		{
			return service;
		}

		public virtual BigInteger getNonce()
		{
			return nonce;
		}

		public virtual DVCSTime getRequestTime()
		{
			return requestTime;
		}

		public virtual GeneralNames getRequester()
		{
			return requester;
		}

		public virtual PolicyInformation getRequestPolicy()
		{
			return requestPolicy;
		}

		public virtual GeneralNames getDVCS()
		{
			return dvcs;
		}

		public virtual GeneralNames getDataLocations()
		{
			return dataLocations;
		}

		public virtual Extensions getExtensions()
		{
			return extensions;
		}
	}

}