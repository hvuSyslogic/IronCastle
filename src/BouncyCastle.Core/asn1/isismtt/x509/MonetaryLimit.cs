using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.isismtt.x509
{


	/// <summary>
	/// Monetary limit for transactions. The QcEuMonetaryLimit QC statement MUST be
	/// used in new certificates in place of the extension/attribute MonetaryLimit
	/// since January 1, 2004. For the sake of backward compatibility with
	/// certificates already in use, components SHOULD support MonetaryLimit (as well
	/// as QcEuLimitValue).
	/// <para>
	/// Indicates a monetary limit within which the certificate holder is authorized
	/// to act. (This value DOES NOT express a limit on the liability of the
	/// certification authority).
	/// <pre>
	///    MonetaryLimitSyntax ::= SEQUENCE
	///    {
	///      currency PrintableString (SIZE(3)),
	///      amount INTEGER,
	///      exponent INTEGER
	///    }
	/// </pre>
	/// </para>
	/// <para>
	/// currency must be the ISO code.
	/// </para>
	/// <para>
	/// value = amount�10*exponent
	/// </para>
	/// </summary>
	public class MonetaryLimit : ASN1Object
	{
		internal DERPrintableString currency;
		internal ASN1Integer amount;
		internal ASN1Integer exponent;

		public static MonetaryLimit getInstance(object obj)
		{
			if (obj == null || obj is MonetaryLimit)
			{
				return (MonetaryLimit)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new MonetaryLimit(ASN1Sequence.getInstance(obj));
			}

			throw new IllegalArgumentException("unknown object in getInstance");
		}

		private MonetaryLimit(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			Enumeration e = seq.getObjects();
			currency = DERPrintableString.getInstance(e.nextElement());
			amount = ASN1Integer.getInstance(e.nextElement());
			exponent = ASN1Integer.getInstance(e.nextElement());
		}

		/// <summary>
		/// Constructor from a given details.
		/// <para>
		/// value = amount�10^exponent
		/// 
		/// </para>
		/// </summary>
		/// <param name="currency"> The currency. Must be the ISO code. </param>
		/// <param name="amount">   The amount </param>
		/// <param name="exponent"> The exponent </param>
		public MonetaryLimit(string currency, int amount, int exponent)
		{
			this.currency = new DERPrintableString(currency, true);
			this.amount = new ASN1Integer(amount);
			this.exponent = new ASN1Integer(exponent);
		}

		public virtual string getCurrency()
		{
			return currency.getString();
		}

		public virtual BigInteger getAmount()
		{
			return amount.getValue();
		}

		public virtual BigInteger getExponent()
		{
			return exponent.getValue();
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///    MonetaryLimitSyntax ::= SEQUENCE
		///    {
		///      currency PrintableString (SIZE(3)),
		///      amount INTEGER,
		///      exponent INTEGER
		///    }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();
			seq.add(currency);
			seq.add(amount);
			seq.add(exponent);

			return new DERSequence(seq);
		}

	}

}