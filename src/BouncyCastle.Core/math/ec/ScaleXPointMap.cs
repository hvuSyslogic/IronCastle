namespace org.bouncycastle.math.ec
{
	public class ScaleXPointMap : ECPointMap
	{
		protected internal readonly ECFieldElement scale;

		public ScaleXPointMap(ECFieldElement scale)
		{
			this.scale = scale;
		}

		public virtual ECPoint map(ECPoint p)
		{
			return p.scaleX(scale);
		}
	}

}