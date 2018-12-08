using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.icao
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// The LDSSecurityObject object (V1.8).
	/// <pre>
	/// LDSSecurityObject ::= SEQUENCE {
	///   version                LDSSecurityObjectVersion,
	///   hashAlgorithm          DigestAlgorithmIdentifier,
	///   dataGroupHashValues    SEQUENCE SIZE (2..ub-DataGroups) OF DataHashGroup,
	///   ldsVersionInfo         LDSVersionInfo OPTIONAL
	///   -- if present, version MUST be v1 }
	/// 
	/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier,
	/// 
	/// LDSSecurityObjectVersion :: INTEGER {V0(0)}
	/// </pre>
	/// </summary>
	public class LDSSecurityObject : ASN1Object, ICAOObjectIdentifiers
	{
		public const int ub_DataGroups = 16;

		private ASN1Integer version = new ASN1Integer(0);
		private AlgorithmIdentifier digestAlgorithmIdentifier;
		private DataGroupHash[] datagroupHash;
		private LDSVersionInfo versionInfo;

		public static LDSSecurityObject getInstance(object obj)
		{
			if (obj is LDSSecurityObject)
			{
				return (LDSSecurityObject)obj;
			}
			else if (obj != null)
			{
				return new LDSSecurityObject(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private LDSSecurityObject(ASN1Sequence seq)
		{
			if (seq == null || seq.size() == 0)
			{
				throw new IllegalArgumentException("null or empty sequence passed.");
			}

			Enumeration e = seq.getObjects();

			// version
			version = ASN1Integer.getInstance(e.nextElement());
			// digestAlgorithmIdentifier
			digestAlgorithmIdentifier = AlgorithmIdentifier.getInstance(e.nextElement());

			ASN1Sequence datagroupHashSeq = ASN1Sequence.getInstance(e.nextElement());

			if (version.getValue().intValue() == 1)
			{
				versionInfo = LDSVersionInfo.getInstance(e.nextElement());
			}

			checkDatagroupHashSeqSize(datagroupHashSeq.size());

			datagroupHash = new DataGroupHash[datagroupHashSeq.size()];
			for (int i = 0; i < datagroupHashSeq.size(); i++)
			{
				datagroupHash[i] = DataGroupHash.getInstance(datagroupHashSeq.getObjectAt(i));
			}
		}

		public LDSSecurityObject(AlgorithmIdentifier digestAlgorithmIdentifier, DataGroupHash[] datagroupHash)
		{
			this.version = new ASN1Integer(0);
			this.digestAlgorithmIdentifier = digestAlgorithmIdentifier;
			this.datagroupHash = copy(datagroupHash);

			checkDatagroupHashSeqSize(datagroupHash.Length);
		}

		public LDSSecurityObject(AlgorithmIdentifier digestAlgorithmIdentifier, DataGroupHash[] datagroupHash, LDSVersionInfo versionInfo)
		{
			this.version = new ASN1Integer(1);
			this.digestAlgorithmIdentifier = digestAlgorithmIdentifier;
			this.datagroupHash = copy(datagroupHash);
			this.versionInfo = versionInfo;

			checkDatagroupHashSeqSize(datagroupHash.Length);
		}

		private void checkDatagroupHashSeqSize(int size)
		{
			if ((size < 2) || (size > ub_DataGroups))
			{
				throw new IllegalArgumentException("wrong size in DataGroupHashValues : not in (2.." + ub_DataGroups + ")");
			}
		}

		public virtual int getVersion()
		{
			return version.getValue().intValue();
		}

		public virtual AlgorithmIdentifier getDigestAlgorithmIdentifier()
		{
			return digestAlgorithmIdentifier;
		}

		public virtual DataGroupHash[] getDatagroupHash()
		{
			return copy(datagroupHash);
		}

		public virtual LDSVersionInfo getVersionInfo()
		{
			return versionInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();

			seq.add(version);
			seq.add(digestAlgorithmIdentifier);

			ASN1EncodableVector seqname = new ASN1EncodableVector();
			for (int i = 0; i < datagroupHash.Length; i++)
			{
				seqname.add(datagroupHash[i]);
			}
			seq.add(new DERSequence(seqname));

			if (versionInfo != null)
			{
				seq.add(versionInfo);
			}

			return new DERSequence(seq);
		}

		private DataGroupHash[] copy(DataGroupHash[] dgHash)
		{
			DataGroupHash[] rv = new DataGroupHash[dgHash.Length];

			JavaSystem.arraycopy(dgHash, 0, rv, 0, rv.Length);

			return rv;
		}
	}

}