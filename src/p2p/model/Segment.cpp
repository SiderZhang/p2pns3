#include "Segment.h"


Segment::Segment(void)
	:bufferedData(0), Active(false)
{
	this->size = SEG_SIZE;
	this->TemporalLayerId = -1;
	this->SpatialLayerId = -1;
	this->QualityLayerId = -1;
	this->index = -1;
}


Segment::~Segment(void)
{
}
