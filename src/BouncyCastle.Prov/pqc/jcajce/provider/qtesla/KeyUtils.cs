using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.qtesla
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using QTESLASecurityCategory = org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
	using Integers = org.bouncycastle.util.Integers;

	public class KeyUtils
	{
		internal static readonly AlgorithmIdentifier AlgID_qTESLA_I = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.qTESLA_I);
		internal static readonly AlgorithmIdentifier AlgID_qTESLA_III_size = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.qTESLA_III_size);
		internal static readonly AlgorithmIdentifier AlgID_qTESLA_III_speed = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.qTESLA_III_speed);
		internal static readonly AlgorithmIdentifier AlgID_qTESLA_p_I = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.qTESLA_p_I);
		internal static readonly AlgorithmIdentifier AlgID_qTESLA_p_III = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.qTESLA_p_III);

		internal static readonly Map categories = new HashMap();

		static KeyUtils()
		{
			categories.put(PQCObjectIdentifiers_Fields.qTESLA_I, Integers.valueOf(QTESLASecurityCategory.HEURISTIC_I));
			categories.put(PQCObjectIdentifiers_Fields.qTESLA_III_size, Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III_SIZE));
			categories.put(PQCObjectIdentifiers_Fields.qTESLA_III_speed, Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III_SPEED));
			categories.put(PQCObjectIdentifiers_Fields.qTESLA_p_I, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_I));
			categories.put(PQCObjectIdentifiers_Fields.qTESLA_p_III, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_III));
		}

		internal static int lookupSecurityCatergory(AlgorithmIdentifier algorithm)
		{
			return ((int?)categories.get(algorithm.getAlgorithm())).Value;
		}

		internal static AlgorithmIdentifier lookupAlgID(int securityCategory)
		{
			switch (securityCategory)
			{
			case QTESLASecurityCategory.HEURISTIC_I:
				return AlgID_qTESLA_I;
			case QTESLASecurityCategory.HEURISTIC_III_SIZE:
				return AlgID_qTESLA_III_size;
			case QTESLASecurityCategory.HEURISTIC_III_SPEED:
				return AlgID_qTESLA_III_speed;
			case QTESLASecurityCategory.PROVABLY_SECURE_I:
				return AlgID_qTESLA_p_I;
			case QTESLASecurityCategory.PROVABLY_SECURE_III:
				return AlgID_qTESLA_p_III;
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}
		}
	}

}