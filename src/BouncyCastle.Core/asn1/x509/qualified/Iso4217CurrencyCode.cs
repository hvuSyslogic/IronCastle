using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509.qualified
{

	/// <summary>
	/// The Iso4217CurrencyCode object.
	/// <pre>
	/// Iso4217CurrencyCode  ::=  CHOICE {
	///       alphabetic              PrintableString (SIZE 3), --Recommended
	///       numeric              INTEGER (1..999) }
	/// -- Alphabetic or numeric currency code as defined in ISO 4217
	/// -- It is recommended that the Alphabetic form is used
	/// </pre>
	/// </summary>
	public class Iso4217CurrencyCode : ASN1Object, ASN1Choice
	{
		internal readonly int ALPHABETIC_MAXSIZE = 3;
		internal readonly int NUMERIC_MINSIZE = 1;
		internal readonly int NUMERIC_MAXSIZE = 999;

		internal ASN1Encodable obj;
		internal int numeric;

		public static Iso4217CurrencyCode getInstance(object obj)
		{
			if (obj == null || obj is Iso4217CurrencyCode)
			{
				return (Iso4217CurrencyCode)obj;
			}

			if (obj is ASN1Integer)
			{
				ASN1Integer numericobj = ASN1Integer.getInstance(obj);
				int numeric = numericobj.getValue().intValue();
				return new Iso4217CurrencyCode(numeric);
			}
			else
			{
			if (obj is DERPrintableString)
			{
				DERPrintableString alphabetic = DERPrintableString.getInstance(obj);
				return new Iso4217CurrencyCode(alphabetic.getString());
			}
			}
			throw new IllegalArgumentException("unknown object in getInstance");
		}

		public Iso4217CurrencyCode(int numeric)
		{
			if (numeric > NUMERIC_MAXSIZE || numeric < NUMERIC_MINSIZE)
			{
				throw new IllegalArgumentException("wrong size in numeric code : not in (" + NUMERIC_MINSIZE + ".." + NUMERIC_MAXSIZE + ")");
			}
			obj = new ASN1Integer(numeric);
		}

		public Iso4217CurrencyCode(string alphabetic)
		{
			if (alphabetic.Length > ALPHABETIC_MAXSIZE)
			{
				throw new IllegalArgumentException("wrong size in alphabetic code : max size is " + ALPHABETIC_MAXSIZE);
			}
			obj = new DERPrintableString(alphabetic);
		}

		public virtual bool isAlphabetic()
		{
			return obj is DERPrintableString;
		}

		public virtual string getAlphabetic()
		{
			return ((DERPrintableString)obj).getString();
		}

		public virtual int getNumeric()
		{
			return ((ASN1Integer)obj).getValue().intValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return obj.toASN1Primitive();
		}
	}

}