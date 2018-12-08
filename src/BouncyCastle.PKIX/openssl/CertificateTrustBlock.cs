namespace org.bouncycastle.openssl
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;

	public class CertificateTrustBlock
	{
		private ASN1Sequence uses;
		private ASN1Sequence prohibitions;
		private string alias;

		public CertificateTrustBlock(Set<ASN1ObjectIdentifier> uses) : this(null, uses, null)
		{
		}

		public CertificateTrustBlock(string alias, Set<ASN1ObjectIdentifier> uses) : this(alias, uses, null)
		{
		}

		public CertificateTrustBlock(string alias, Set<ASN1ObjectIdentifier> uses, Set<ASN1ObjectIdentifier> prohibitions)
		{
			this.alias = alias;
			this.uses = toSequence(uses);
			this.prohibitions = toSequence(prohibitions);
		}

		public CertificateTrustBlock(byte[] encoded)
		{
			ASN1Sequence seq = ASN1Sequence.getInstance(encoded);

			for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
			{
				ASN1Encodable obj = (ASN1Encodable)en.nextElement();

				if (obj is ASN1Sequence)
				{
					this.uses = ASN1Sequence.getInstance(obj);
				}
				else if (obj is ASN1TaggedObject)
				{
					this.prohibitions = ASN1Sequence.getInstance((ASN1TaggedObject)obj, false);
				}
				else if (obj is DERUTF8String)
				{
					this.alias = DERUTF8String.getInstance(obj).getString();
				}
			}
		}

		public virtual string getAlias()
		{
			return alias;
		}

		public virtual Set<ASN1ObjectIdentifier> getUses()
		{
			return toSet(uses);
		}

		public virtual Set<ASN1ObjectIdentifier> getProhibitions()
		{
			return toSet(prohibitions);
		}

		private Set<ASN1ObjectIdentifier> toSet(ASN1Sequence seq)
		{
			if (seq != null)
			{
				Set<ASN1ObjectIdentifier> oids = new HashSet<ASN1ObjectIdentifier>(seq.size());

				for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
				{
					oids.add(ASN1ObjectIdentifier.getInstance(en.nextElement()));
				}

				return oids;
			}

			return Collections.EMPTY_SET;
		}

		private ASN1Sequence toSequence(Set<ASN1ObjectIdentifier> oids)
		{
			if (oids == null || oids.isEmpty())
			{
				return null;
			}

			ASN1EncodableVector v = new ASN1EncodableVector();

			for (Iterator it = oids.iterator(); it.hasNext();)
			{
			   v.add((ASN1Encodable)it.next());
			}

			return new DERSequence(v);
		}

		public virtual ASN1Sequence toASN1Sequence()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (uses != null)
			{
			   v.add(uses);
			}
			if (prohibitions != null)
			{
				v.add(new DERTaggedObject(false, 0, prohibitions));
			}
			if (!string.ReferenceEquals(alias, null))
			{
				v.add(new DERUTF8String(alias));
			}

			return new DERSequence(v);
		}
	}

}