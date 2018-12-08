using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmp
{


	public class PKIFreeText : ASN1Object
	{
		internal ASN1Sequence strings;

		public static PKIFreeText getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static PKIFreeText getInstance(object obj)
		{
			if (obj is PKIFreeText)
			{
				return (PKIFreeText)obj;
			}
			else if (obj != null)
			{
				return new PKIFreeText(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private PKIFreeText(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();
			while (e.hasMoreElements())
			{
				if (!(e.nextElement() is DERUTF8String))
				{
					throw new IllegalArgumentException("attempt to insert non UTF8 STRING into PKIFreeText");
				}
			}

			strings = seq;
		}

		public PKIFreeText(DERUTF8String p)
		{
			strings = new DERSequence(p);
		}

		public PKIFreeText(string p) : this(new DERUTF8String(p))
		{
		}

		public PKIFreeText(DERUTF8String[] strs)
		{
			strings = new DERSequence(strs);
		}

		public PKIFreeText(string[] strs)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < strs.Length; i++)
			{
				v.add(new DERUTF8String(strs[i]));
			}
			strings = new DERSequence(v);
		}

		/// <summary>
		/// Return the number of string elements present.
		/// </summary>
		/// <returns> number of elements present. </returns>
		public virtual int size()
		{
			return strings.size();
		}

		/// <summary>
		/// Return the UTF8STRING at index i.
		/// </summary>
		/// <param name="i"> index of the string of interest </param>
		/// <returns> the string at index i. </returns>
		public virtual DERUTF8String getStringAt(int i)
		{
			return (DERUTF8String)strings.getObjectAt(i);
		}

		/// <summary>
		/// <pre>
		/// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return strings;
		}
	}

}