#pragma once
#include <assert.h>
#include <string>
#include <sstream>
using namespace std;

#include "Global.h"

class Segment
{
private:
	float size;
	int index;

	int TemporalLayerId;
	int SpatialLayerId;
	int QualityLayerId;

	// 已经缓冲的数据量
	float bufferedData;

	// 是否激活
	// 激活态的Segment是会进行传输的
	bool Active;


public:
	Segment(void);
	~Segment(void);

	float getSize() const
	{
		return size;
	}

	int getIndex() const 
	{
		return index;
	}

	int getTemporalLayerID() const 
	{
		return TemporalLayerId;
	}

	void setTemporalLayerID(int layerID)
	{
		this->TemporalLayerId = layerID;
	}

	int getSpatialLayerId() const 
	{
		return SpatialLayerId;
	}

	void setSpatialLayerId(int sLayerId)
	{
		this->SpatialLayerId = sLayerId;
	}

	int getQualityLayerId()
	{
		return QualityLayerId;
	}

	void setQualityLayerId(int qLayerId)
	{
		this->QualityLayerId = qLayerId;
	}

	void setIndex(int Index)
	{
		this->index = Index;
	}

	bool operator == (const Segment& rhs)
	{
		if ((this->getIndex() == rhs.getIndex()) && (this->getTemporalLayerID() == rhs.getTemporalLayerID()))
			return true;
		else
			return false;
	}

	// 判断一个Segment是否缓冲完成
	bool isBufferOver()
	{
		return bufferedData >= size;
	}

	float getRestBufferData()
	{
		return size - bufferedData;
	}

	float getBufferedSize()
	{
		return bufferedData;
	}

	void setBufferSize(float data)
	{
		if (data > size)
			bufferedData = size;

		bufferedData = data;
	}

	bool isActive()
	{
		return this->Active;
	}

	void ActiveSeg()
	{
		if (Active == true)
			assert(false);

		this->Active = true;
	}

	void UnactiveSeg()
	{
		assert(Active == true);
		Active = false;
	}

	bool isWaiting()
	{
		if (isActive() && !this->isBufferOver())
			return true;
		else
			return false;
	}

	string toString(bool onlyActive = true)
	{
		stringstream stream;
		if (onlyActive)
		{
			stream<<index<<", "<<this->TemporalLayerId<<", "<<endl;
		}

		return stream.str();
	}
};