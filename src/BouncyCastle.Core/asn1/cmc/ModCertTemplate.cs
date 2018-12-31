using org.bouncycastle.asn1.crmf;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{
	
	/// <summary>
	/// <pre>
	/// id-cmc-modCertTemplate OBJECT IDENTIFIER ::= {id-cmc 31}
	/// 
	/// ModCertTemplate ::= SEQUENCE {
	///    pkiDataReference             BodyPartPath,
	///    certReferences               BodyPartList,
	///    replace                      BOOLEAN DEFAULT TRUE,
	///    certTemplate                 CertTemplate
	/// }
	/// </pre>
	/// </summary>
	public class ModCertTemplate : ASN1Object
	{
		private readonly BodyPartPath pkiDataReference;
		private readonly BodyPartList certReferences;
		private readonly bool replace;
		private readonly CertTemplate certTemplate;

		public ModCertTemplate(BodyPartPath pkiDataReference, BodyPartList certReferences, bool replace, CertTemplate certTemplate)
		{
			this.pkiDataReference = pkiDataReference;
			this.certReferences = certReferences;
			this.replace = replace;
			this.certTemplate = certTemplate;
		}

		private ModCertTemplate(ASN1Sequence seq)
		{
			if (seq.size() != 4 && seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.pkiDataReference = BodyPartPath.getInstance(seq.getObjectAt(0));
			this.certReferences = BodyPartList.getInstance(seq.getObjectAt(1));

			if (seq.size() == 4)
			{
				this.replace = ASN1Boolean.getInstance(seq.getObjectAt(2)).isTrue();
				this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(3));
			}
			else
			{
				this.replace = true;
				this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(2));
			}
		}

		public static ModCertTemplate getInstance(object o)
		{
			if (o is ModCertTemplate)
			{
				return (ModCertTemplate)o;
			}

			if (o != null)
			{
				return new ModCertTemplate(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual BodyPartPath getPkiDataReference()
		{
			return pkiDataReference;
		}

		public virtual BodyPartList getCertReferences()
		{
			return certReferences;
		}

		public virtual bool isReplacingFields()
		{
			return replace;
		}

		public virtual CertTemplate getCertTemplate()
		{
			return certTemplate;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pkiDataReference);
			v.add(certReferences);
			if (!replace)
			{
				v.add(ASN1Boolean.getInstance(replace));
			}
			v.add(certTemplate);

			return new DERSequence(v);
		}
	}

}