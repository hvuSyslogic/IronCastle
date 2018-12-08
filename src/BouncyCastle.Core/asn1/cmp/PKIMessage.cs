using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmp
{


	public class PKIMessage : ASN1Object
	{
		private PKIHeader header;
		private PKIBody body;
		private DERBitString protection;
		private ASN1Sequence extraCerts;

		private PKIMessage(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();

			header = PKIHeader.getInstance(en.nextElement());
			body = PKIBody.getInstance(en.nextElement());

			while (en.hasMoreElements())
			{
				ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

				if (tObj.getTagNo() == 0)
				{
					protection = DERBitString.getInstance(tObj, true);
				}
				else
				{
					extraCerts = ASN1Sequence.getInstance(tObj, true);
				}
			}
		}

		public static PKIMessage getInstance(object o)
		{
			if (o is PKIMessage)
			{
				return (PKIMessage)o;
			}
			else if (o != null)
			{
				return new PKIMessage(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// Creates a new PKIMessage.
		/// </summary>
		/// <param name="header">     message header </param>
		/// <param name="body">       message body </param>
		/// <param name="protection"> message protection (may be null) </param>
		/// <param name="extraCerts"> extra certificates (may be null) </param>
		public PKIMessage(PKIHeader header, PKIBody body, DERBitString protection, CMPCertificate[] extraCerts)
		{
			this.header = header;
			this.body = body;
			this.protection = protection;
			if (extraCerts != null)
			{
				ASN1EncodableVector v = new ASN1EncodableVector();
				for (int i = 0; i < extraCerts.Length; i++)
				{
					v.add(extraCerts[i]);
				}
				this.extraCerts = new DERSequence(v);
			}
		}

		public PKIMessage(PKIHeader header, PKIBody body, DERBitString protection) : this(header, body, protection, null)
		{
		}

		public PKIMessage(PKIHeader header, PKIBody body) : this(header, body, null, null)
		{
		}

		public virtual PKIHeader getHeader()
		{
			return header;
		}

		public virtual PKIBody getBody()
		{
			return body;
		}

		public virtual DERBitString getProtection()
		{
			return protection;
		}

		public virtual CMPCertificate[] getExtraCerts()
		{
			if (extraCerts == null)
			{
				return null;
			}

			CMPCertificate[] results = new CMPCertificate[extraCerts.size()];

			for (int i = 0; i < results.Length; i++)
			{
				results[i] = CMPCertificate.getInstance(extraCerts.getObjectAt(i));
			}
			return results;
		}

		/// <summary>
		/// <pre>
		/// PKIMessage ::= SEQUENCE {
		///                  header           PKIHeader,
		///                  body             PKIBody,
		///                  protection   [0] PKIProtection OPTIONAL,
		///                  extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
		///                                                                     OPTIONAL
		/// }
		/// </pre>
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(header);
			v.add(body);

			addOptional(v, 0, protection);
			addOptional(v, 1, extraCerts);

			return new DERSequence(v);
		}

		private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(new DERTaggedObject(true, tagNo, obj));
			}
		}
	}

}