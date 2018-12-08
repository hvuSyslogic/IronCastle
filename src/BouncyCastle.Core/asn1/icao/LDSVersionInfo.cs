using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.icao
{

	public class LDSVersionInfo : ASN1Object
	{
		private DERPrintableString ldsVersion;
		private DERPrintableString unicodeVersion;

		public LDSVersionInfo(string ldsVersion, string unicodeVersion)
		{
			this.ldsVersion = new DERPrintableString(ldsVersion);
			this.unicodeVersion = new DERPrintableString(unicodeVersion);
		}

		private LDSVersionInfo(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("sequence wrong size for LDSVersionInfo");
			}

			this.ldsVersion = DERPrintableString.getInstance(seq.getObjectAt(0));
			this.unicodeVersion = DERPrintableString.getInstance(seq.getObjectAt(1));
		}

		public static LDSVersionInfo getInstance(object obj)
		{
			if (obj is LDSVersionInfo)
			{
				return (LDSVersionInfo)obj;
			}
			else if (obj != null)
			{
				return new LDSVersionInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual string getLdsVersion()
		{
			return ldsVersion.getString();
		}

		public virtual string getUnicodeVersion()
		{
			return unicodeVersion.getString();
		}

		/// <summary>
		/// <pre>
		/// LDSVersionInfo ::= SEQUENCE {
		///    ldsVersion PRINTABLE STRING
		///    unicodeVersion PRINTABLE STRING
		///  }
		/// </pre> </summary>
		/// <returns>  an ASN.1 primitive composition of this LDSVersionInfo. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(ldsVersion);
			v.add(unicodeVersion);

			return new DERSequence(v);
		}
	}

}