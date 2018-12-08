namespace org.bouncycastle.math.ec
{
	public class ScaleYPointMap : ECPointMap
	{
		protected internal readonly ECFieldElement scale;

		public ScaleYPointMap(ECFieldElement scale)
		{
			this.scale = scale;
		}

		public virtual ECPoint map(ECPoint p)
		{
			return p.scaleY(scale);
		}
	}

}