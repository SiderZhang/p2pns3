#include "Video.h"
#include "Global.h"

#include <assert.h>

int Video::chokeCount;
int Video::layerCount;
Video Video::instance;

Video::Video(void)
{
	triangleIndex = 0;
	this->avgLayerCount = 0;
	segmentMap.resize(VIDEO_TOTAL_CHOKE, NULL);
}

Video::~Video(void)
{
	vector<vector<Segment*>*>::iterator chokeIter = segmentMap.begin();
	for (;chokeIter != segmentMap.end();++chokeIter)
	{
		vector<Segment*>* layers = *chokeIter;
		if (layers == NULL)
			continue;

		for (vector<Segment*>::iterator layerIter = layers->begin();layerIter != layers->end();++layerIter)
		{
			assert(*layerIter != NULL);
			delete *layerIter;
			*layerIter = NULL;
		}

		delete layers;
		(*chokeIter) = NULL;
	}
}

Video* Video::getFullVideoCopy()
{
	Video* video = new Video();

	for (int index = 0;index < Video::getInstance().getTotalChokeCount();++index)
	{
		for (int layer = 0;layer < Video::getInstance().getLayerCount();++layer)
		{
			Segment* seg = new Segment();
			seg->setIndex(index);
			seg->setTemporalLayerID(layer);
			seg->setBufferSize(seg->getSize());
			video->insertSegment(seg);
		}
	}

	return video;
}
	
Video* Video::getEmptyVideoCopy()
{	
	Video* video = new Video();

	for (int index = 0;index < Video::getInstance().getTotalChokeCount();++index)
	{
		for (int layer = 0;layer < Video::getInstance().getLayerCount();++layer)
		{
			Segment* seg = new Segment();
			seg->setIndex(index);
			seg->setTemporalLayerID(layer);
			seg->setBufferSize(0);
			video->insertSegment(seg);
		}
	}

	return video;
}

void Video::insertSegment(Segment* seg)
{	
	int index = seg->getIndex();

	vector<Segment*>* myMap = segmentMap.at(index);	
	if (myMap == NULL)
	{
		vector<Segment*>* vec = new vector<Segment*>();
		vec->resize(VIDEO_LAYER_COUNT, NULL);
		segmentMap.at(index) = vec;
		myMap = vec;
	}

	assert(myMap->at(seg->getTemporalLayerID()) == NULL);
	myMap->at(seg->getTemporalLayerID()) = seg;
}
	
float Video::calcDataRate(int decodedLimit)
{	
	int bufferSegCount = 0;
	if (getBuffedIndex() == -1)
		return -1;

	for (int i = 0;i < this->getBuffedIndex();++i)
	{
		vector<Segment*>* pMap = segmentMap.at(i);

		for (int i = 0;i < layerCount;++i)
		{
			if (pMap->at(i)->isBufferOver())
				bufferSegCount += 1;
			else
				break;
		}
	}

	int totalSegCount = (this->getBuffedIndex() + 1) * decodedLimit;

	return bufferSegCount * 1.0f / totalSegCount;
}

int Video::getBuffedIndex()
{
	int totalChokeCount = Video::getTotalChokeCount();

	for (int i = 0;i < totalChokeCount;++i)
	{
		if (BufferedLayer(i) < 0)
		{
			return i - 1;
		}
	}

	return totalChokeCount - 1;
}
	
int Video::BufferedLayer(int index)
{
	vector<Segment*>* pMap = segmentMap.at(index);

	assert(pMap != NULL);

	int layerCount = Video::getLayerCount();
	for (int i = 0;i < layerCount;++i)
	{
		if (!pMap->at(i)->isBufferOver())
			return i - 1;
	}

	return layerCount - 1;
}
	
Segment* Video::getSegment(int index, int layer)
{
	vector<Segment*>* outerIter = segmentMap.at(index);
	if (outerIter == NULL)
	{
		outerIter = new vector<Segment*>();
		assert(segmentMap.at(index) == NULL);
		segmentMap.at(index) = outerIter;
	}


	Segment* innerIter = outerIter->at(layer);
	if (innerIter == NULL)
	{
		innerIter = new Segment();
		assert(outerIter->at(layer) == NULL);
		outerIter->at(layer) = innerIter;
	}

	return innerIter;
}
	
bool Video::hasSegment(int index, int layer)
{
	Segment* seg = getSegment(index, layer);
	if (seg == NULL)
		return false;

	return seg->isBufferOver();
}

void Video::updateTrangleIndex(int decodeLimit, stringstream& logger)
{	
	this->segCount = 0;
	this->avgLayerCount = 0;
	if (this->getBuffedIndex() >= 0)
	{
		for (int i = 0;i < getBuffedIndex();++i)
		{
			int count = this->BufferedLayer(i);
			this->avgLayerCount += count;
			this->segCount += count;
		}
		this->avgLayerCount /= (getBuffedIndex() + 1);
	}

	this->triangleIndex = getBuffedIndex() + this->avgLayerCount;

	logger<<"tri index: "<<triangleIndex<<", buffered Index: "<<getBuffedIndex()<<", avg layer count: "<<this->avgLayerCount<<";";
}
	
int Video::chokeLayerCount(int index)
{
	int result = 0;
	vector<Segment*>* outerIter = segmentMap.at(index);
	if (outerIter == NULL)
		return result;

	vector<Segment*>* map = outerIter;

	for (int i = 0;i < VIDEO_LAYER_COUNT;++i)
	{
		if (map->at(i) == NULL)
			break;
		result++;
	}

	return result;
}
