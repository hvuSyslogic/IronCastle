using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.tsp
{


	public class Accuracy : ASN1Object
	{
		internal ASN1Integer seconds;

		internal ASN1Integer millis;

		internal ASN1Integer micros;

		// constantes
		protected internal const int MIN_MILLIS = 1;

		protected internal const int MAX_MILLIS = 999;

		protected internal const int MIN_MICROS = 1;

		protected internal const int MAX_MICROS = 999;

		public Accuracy()
		{
		}

		public Accuracy(ASN1Integer seconds, ASN1Integer millis, ASN1Integer micros)
		{
			this.seconds = seconds;

			//Verifications
			if (millis != null && (millis.getValue().intValue() < MIN_MILLIS || millis.getValue().intValue() > MAX_MILLIS))
			{
				throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
			}
			else
			{
				this.millis = millis;
			}

			if (micros != null && (micros.getValue().intValue() < MIN_MICROS || micros.getValue().intValue() > MAX_MICROS))
			{
				throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
			}
			else
			{
				this.micros = micros;
			}

		}

		private Accuracy(ASN1Sequence seq)
		{
			seconds = null;
			millis = null;
			micros = null;

			for (int i = 0; i < seq.size(); i++)
			{
				// seconds
				if (seq.getObjectAt(i) is ASN1Integer)
				{
					seconds = (ASN1Integer) seq.getObjectAt(i);
				}
				else if (seq.getObjectAt(i) is ASN1TaggedObject)
				{
					ASN1TaggedObject extra = (ASN1TaggedObject)seq.getObjectAt(i);

					switch (extra.getTagNo())
					{
					case 0:
						millis = ASN1Integer.getInstance(extra, false);
						if (millis.getValue().intValue() < MIN_MILLIS || millis.getValue().intValue() > MAX_MILLIS)
						{
							throw new IllegalArgumentException("Invalid millis field : not in (1..999).");
						}
						break;
					case 1:
						micros = ASN1Integer.getInstance(extra, false);
						if (micros.getValue().intValue() < MIN_MICROS || micros.getValue().intValue() > MAX_MICROS)
						{
							throw new IllegalArgumentException("Invalid micros field : not in (1..999).");
						}
						break;
					default:
						throw new IllegalArgumentException("Invalig tag number");
					}
				}
			}
		}

		public static Accuracy getInstance(object o)
		{
			if (o is Accuracy)
			{
				return (Accuracy) o;
			}

			if (o != null)
			{
				return new Accuracy(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual ASN1Integer getSeconds()
		{
			return seconds;
		}

		public virtual ASN1Integer getMillis()
		{
			return millis;
		}

		public virtual ASN1Integer getMicros()
		{
			return micros;
		}

		/// <summary>
		/// <pre>
		/// Accuracy ::= SEQUENCE {
		///             seconds        INTEGER              OPTIONAL,
		///             millis     [0] INTEGER  (1..999)    OPTIONAL,
		///             micros     [1] INTEGER  (1..999)    OPTIONAL
		///             }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{

			ASN1EncodableVector v = new ASN1EncodableVector();

			if (seconds != null)
			{
				v.add(seconds);
			}

			if (millis != null)
			{
				v.add(new DERTaggedObject(false, 0, millis));
			}

			if (micros != null)
			{
				v.add(new DERTaggedObject(false, 1, micros));
			}

			return new DERSequence(v);
		}
	}

}