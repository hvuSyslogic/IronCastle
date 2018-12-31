using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.tsp
{

		
	public class TSTInfo : ASN1Object
	{
		private ASN1Integer version;
		private ASN1ObjectIdentifier tsaPolicyId;
		private MessageImprint messageImprint;
		private ASN1Integer serialNumber;
		private ASN1GeneralizedTime genTime;
		private Accuracy accuracy;
		private ASN1Boolean ordering;
		private ASN1Integer nonce;
		private GeneralName tsa;
		private Extensions extensions;

		public static TSTInfo getInstance(object o)
		{
			if (o is TSTInfo)
			{
				return (TSTInfo)o;
			}
			else if (o != null)
			{
				return new TSTInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private TSTInfo(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			// version
			version = ASN1Integer.getInstance(e.nextElement());

			// tsaPolicy
			tsaPolicyId = ASN1ObjectIdentifier.getInstance(e.nextElement());

			// messageImprint
			messageImprint = MessageImprint.getInstance(e.nextElement());

			// serialNumber
			serialNumber = ASN1Integer.getInstance(e.nextElement());

			// genTime
			genTime = ASN1GeneralizedTime.getInstance(e.nextElement());

			// default for ordering
			ordering = ASN1Boolean.getInstance(false);

			while (e.hasMoreElements())
			{
				ASN1Object o = (ASN1Object) e.nextElement();

				if (o is ASN1TaggedObject)
				{
					ASN1TaggedObject tagged = (ASN1TaggedObject) o;

					switch (tagged.getTagNo())
					{
					case 0:
						tsa = GeneralName.getInstance(tagged, true);
						break;
					case 1:
						extensions = Extensions.getInstance(tagged, false);
						break;
					default:
						throw new IllegalArgumentException("Unknown tag value " + tagged.getTagNo());
					}
				}
				else if (o is ASN1Sequence || o is Accuracy)
				{
					accuracy = Accuracy.getInstance(o);
				}
				else if (o is ASN1Boolean)
				{
					ordering = ASN1Boolean.getInstance(o);
				}
				else if (o is ASN1Integer)
				{
					nonce = ASN1Integer.getInstance(o);
				}

			}
		}

		public TSTInfo(ASN1ObjectIdentifier tsaPolicyId, MessageImprint messageImprint, ASN1Integer serialNumber, ASN1GeneralizedTime genTime, Accuracy accuracy, ASN1Boolean ordering, ASN1Integer nonce, GeneralName tsa, Extensions extensions)
		{
			version = new ASN1Integer(1);
			this.tsaPolicyId = tsaPolicyId;
			this.messageImprint = messageImprint;
			this.serialNumber = serialNumber;
			this.genTime = genTime;

			this.accuracy = accuracy;
			this.ordering = ordering;
			this.nonce = nonce;
			this.tsa = tsa;
			this.extensions = extensions;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual MessageImprint getMessageImprint()
		{
			return messageImprint;
		}

		public virtual ASN1ObjectIdentifier getPolicy()
		{
			return tsaPolicyId;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		public virtual Accuracy getAccuracy()
		{
			return accuracy;
		}

		public virtual ASN1GeneralizedTime getGenTime()
		{
			return genTime;
		}

		public virtual ASN1Boolean getOrdering()
		{
			return ordering;
		}

		public virtual ASN1Integer getNonce()
		{
			return nonce;
		}

		public virtual GeneralName getTsa()
		{
			return tsa;
		}

		public virtual Extensions getExtensions()
		{
			return extensions;
		}

		/// <summary>
		/// <pre>
		/// 
		///     TSTInfo ::= SEQUENCE  {
		///        version                      INTEGER  { v1(1) },
		///        policy                       TSAPolicyId,
		///        messageImprint               MessageImprint,
		///          -- MUST have the same value as the similar field in
		///          -- TimeStampReq
		///        serialNumber                 INTEGER,
		///         -- Time-Stamping users MUST be ready to accommodate integers
		///         -- up to 160 bits.
		///        genTime                      GeneralizedTime,
		///        accuracy                     Accuracy                 OPTIONAL,
		///        ordering                     BOOLEAN             DEFAULT FALSE,
		///        nonce                        INTEGER                  OPTIONAL,
		///          -- MUST be present if the similar field was present
		///          -- in TimeStampReq.  In that case it MUST have the same value.
		///        tsa                          [0] GeneralName          OPTIONAL,
		///        extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
		/// 
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();
			seq.add(version);

			seq.add(tsaPolicyId);
			seq.add(messageImprint);
			seq.add(serialNumber);
			seq.add(genTime);

			if (accuracy != null)
			{
				seq.add(accuracy);
			}

			if (ordering != null && ordering.isTrue())
			{
				seq.add(ordering);
			}

			if (nonce != null)
			{
				seq.add(nonce);
			}

			if (tsa != null)
			{
				seq.add(new DERTaggedObject(true, 0, tsa));
			}

			if (extensions != null)
			{
				seq.add(new DERTaggedObject(false, 1, extensions));
			}

			return new DERSequence(seq);
		}
	}

}