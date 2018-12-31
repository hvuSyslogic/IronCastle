using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.cmc
{
	
	public class Utils
	{
		internal static BodyPartID[] toBodyPartIDArray(ASN1Sequence bodyPartIDs)
		{
			BodyPartID[] ids = new BodyPartID[bodyPartIDs.size()];

			for (int i = 0; i != bodyPartIDs.size(); i++)
			{
				ids[i] = BodyPartID.getInstance(bodyPartIDs.getObjectAt(i));
			}

			return ids;
		}

		internal static BodyPartID[] clone(BodyPartID[] ids)
		{
			BodyPartID[] tmp = new BodyPartID[ids.Length];

			JavaSystem.arraycopy(ids, 0, tmp, 0, ids.Length);

			return tmp;
		}

		internal static Extension[] clone(Extension[] ids)
		{
			Extension[] tmp = new Extension[ids.Length];

			JavaSystem.arraycopy(ids, 0, tmp, 0, ids.Length);

			return tmp;
		}
	}

}